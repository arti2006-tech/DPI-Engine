package com.dpi.engine;

import com.dpi.model.FiveTuple;
import com.dpi.parser.PacketParser;
import com.dpi.parser.ParsedPacket;
import com.dpi.pcap.PcapReader;
import com.dpi.pcap.PcapWriter;
import com.dpi.pcap.RawPacket;
import com.dpi.rules.RuleManager;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Multi-threaded engine (dpi_mt.cpp):
 * Reader -> LoadBalancer threads -> FastPath threads -> output queue -> writer thread.
 *
 * Shutdown uses "poison pill" packets that flow down the pipeline, so nothing is lost
 * and no sleep()/timeouts are needed.
 */
public final class PipelineEngine {
    static final int QUEUE_CAPACITY = 10_000;

    public record Config(int numLbs, int fpsPerLb) {
        public Config { if (numLbs < 1 || fpsPerLb < 1) throw new IllegalArgumentException("--lbs and --fps must be >= 1"); }
    }

    private final Config config;
    private final RuleManager rules;

    public PipelineEngine(Config config, RuleManager rules) {
        this.config = config;
        this.rules = rules;
    }

    public void process(Path input, Path output) throws IOException {
        Stats stats = new Stats();
        BlockingQueue<Packet> outputQueue = new ArrayBlockingQueue<>(QUEUE_CAPACITY);

        List<FastPath> fps = new ArrayList<>();
        for (int i = 0; i < config.numLbs() * config.fpsPerLb(); i++) fps.add(new FastPath(rules, stats, outputQueue));

        List<LoadBalancer> lbs = new ArrayList<>();
        for (int lb = 0; lb < config.numLbs(); lb++) {
            int start = lb * config.fpsPerLb();
            lbs.add(new LoadBalancer(new ArrayList<>(fps.subList(start, start + config.fpsPerLb())), config.numLbs()));
        }

        try (PcapReader reader = new PcapReader(input);
             PcapWriter writer = new PcapWriter(output, reader.header())) {

            AtomicReference<Throwable> writerError = new AtomicReference<>();
            Thread writerThread = new Thread(() -> {
                try {
                    while (true) {
                        Packet p = outputQueue.take();
                        if (p == Packet.POISON) return;
                        writer.write(p.tsSec(), p.tsUsec(), p.data());
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (IOException e) {
                    writerError.set(e);
                }
            }, "output-writer");

            List<Thread> fpThreads = new ArrayList<>();
            List<Thread> lbThreads = new ArrayList<>();
            for (int i = 0; i < fps.size(); i++) fpThreads.add(new Thread(fps.get(i), "fp-" + i));
            for (int i = 0; i < lbs.size(); i++) lbThreads.add(new Thread(lbs.get(i), "lb-" + i));

            writerThread.start();
            fpThreads.forEach(Thread::start);
            lbThreads.forEach(Thread::start);

            try {
                // ---- Reader (this thread) ----
                System.out.println("[Reader] Processing packets...");
                int packetId = 0;
                RawPacket raw;
                while ((raw = reader.next()) != null) {
                    ParsedPacket p = PacketParser.parse(raw);
                    if (p == null || !p.hasIp || (!p.hasTcp && !p.hasUdp)) continue;

                    FiveTuple tuple = new FiveTuple(p.srcIp, p.destIp, p.srcPort, p.destPort, p.protocol);
                    Packet pkt = new Packet(packetId++, raw.tsSec(), raw.tsUsec(), tuple, raw.data(),
                                            p.tcpFlags, p.payloadOffset, p.payloadLength);

                    stats.totalPackets.incrementAndGet();
                    stats.totalBytes.addAndGet(pkt.data().length);
                    (p.hasTcp ? stats.tcpPackets : stats.udpPackets).incrementAndGet();

                    lbs.get(tuple.flowHash() % lbs.size()).input.put(pkt);
                }
                System.out.println("[Reader] Done reading " + packetId + " packets");

                // ---- Orderly shutdown: LBs -> FPs -> writer ----
                for (LoadBalancer lb : lbs) lb.input.put(Packet.POISON);
                for (Thread t : lbThreads) t.join();
                for (Thread t : fpThreads) t.join();
                outputQueue.put(Packet.POISON);
                writerThread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while processing", e);
            }

            if (writerError.get() != null) throw new IOException("Output write failed", writerError.get());
        }

        List<String> threadLines = new ArrayList<>();
        for (int i = 0; i < lbs.size(); i++) threadLines.add(String.format("LB%d dispatched: %10d", i, lbs.get(i).dispatched.get()));
        for (int i = 0; i < fps.size(); i++) threadLines.add(String.format("FP%d processed:  %10d", i, fps.get(i).processed.get()));
        Report.print(stats, -1, threadLines);
    }
}
