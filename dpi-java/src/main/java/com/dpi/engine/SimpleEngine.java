package com.dpi.engine;

import com.dpi.model.FiveTuple;
import com.dpi.model.Flow;
import com.dpi.model.Ip;
import com.dpi.parser.PacketParser;
import com.dpi.parser.ParsedPacket;
import com.dpi.pcap.PcapReader;
import com.dpi.pcap.PcapWriter;
import com.dpi.pcap.RawPacket;
import com.dpi.rules.RuleManager;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/** Single-threaded engine (main_working.cpp). Best for learning and small captures. */
public final class SimpleEngine {
    private final RuleManager rules;

    public SimpleEngine(RuleManager rules) {
        this.rules = rules;
    }

    public void process(Path input, Path output) throws IOException {
        Stats stats = new Stats();
        Map<FiveTuple, Flow> flows = new HashMap<>();

        try (PcapReader reader = new PcapReader(input);
             PcapWriter writer = new PcapWriter(output, reader.header())) {

            System.out.println("[DPI] Processing packets...");
            RawPacket raw;
            while ((raw = reader.next()) != null) {
                ParsedPacket p = PacketParser.parse(raw);
                if (p == null || !p.hasIp || (!p.hasTcp && !p.hasUdp)) continue;

                FiveTuple tuple = new FiveTuple(p.srcIp, p.destIp, p.srcPort, p.destPort, p.protocol);
                byte[] data = raw.data();

                stats.totalPackets.incrementAndGet();
                stats.totalBytes.addAndGet(data.length);
                (p.hasTcp ? stats.tcpPackets : stats.udpPackets).incrementAndGet();

                Flow flow = flows.computeIfAbsent(tuple, Flow::new);
                flow.packets++;
                flow.bytes += data.length;

                if (!flow.classified) {
                    FlowClassifier.classify(tuple, data, p.payloadOffset, p.payloadLength, flow);
                }

                if (!flow.blocked) {
                    flow.blocked = rules.isBlocked(tuple.srcIp(), flow.appType, flow.sni);
                    if (flow.blocked) {
                        System.out.println("[BLOCKED] " + Ip.format(tuple.srcIp()) + " -> " + Ip.format(tuple.dstIp())
                            + " (" + flow.appType + (flow.sni.isEmpty() ? "" : ": " + flow.sni) + ")");
                    }
                }

                stats.recordApp(flow.appType, flow.sni);

                if (flow.blocked) {
                    stats.dropped.incrementAndGet();
                } else {
                    stats.forwarded.incrementAndGet();
                    writer.write(raw.tsSec(), raw.tsUsec(), data);
                }
            }
        }

        Report.print(stats, flows.size(), null);
    }
}
