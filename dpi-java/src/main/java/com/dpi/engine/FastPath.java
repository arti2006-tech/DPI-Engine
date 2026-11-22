package com.dpi.engine;

import com.dpi.model.FiveTuple;
import com.dpi.model.Flow;
import com.dpi.rules.RuleManager;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

/**
 * One fast-path thread: owns a private flow table, classifies packets and decides forward/drop.
 * Because the load balancers always send the same 5-tuple here, the flow table needs no locking.
 */
final class FastPath implements Runnable {
    final BlockingQueue<Packet> input = new ArrayBlockingQueue<>(PipelineEngine.QUEUE_CAPACITY);
    final AtomicLong processed = new AtomicLong();

    private final RuleManager rules;
    private final Stats stats;
    private final BlockingQueue<Packet> output;
    private final Map<FiveTuple, Flow> flows = new HashMap<>();

    FastPath(RuleManager rules, Stats stats, BlockingQueue<Packet> output) {
        this.rules = rules;
        this.stats = stats;
        this.output = output;
    }

    @Override
    public void run() {
        try {
            while (true) {
                Packet pkt = input.take();
                if (pkt == Packet.POISON) return;
                processed.incrementAndGet();

                Flow flow = flows.computeIfAbsent(pkt.tuple(), Flow::new);
                flow.packets++;
                flow.bytes += pkt.data().length;

                if (!flow.classified) {
                    FlowClassifier.classify(pkt.tuple(), pkt.data(), pkt.payloadOffset(), pkt.payloadLength(), flow);
                }
                if (!flow.blocked) {
                    flow.blocked = rules.isBlocked(pkt.tuple().srcIp(), flow.appType, flow.sni);
                }

                stats.recordApp(flow.appType, flow.sni);

                if (flow.blocked) {
                    stats.dropped.incrementAndGet();
                } else {
                    stats.forwarded.incrementAndGet();
                    output.put(pkt);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
