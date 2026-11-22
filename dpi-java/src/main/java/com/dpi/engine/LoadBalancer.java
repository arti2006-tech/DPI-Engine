package com.dpi.engine;

import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

/** Spreads packets across its fast paths using a hash of the 5-tuple (same flow -> same fast path). */
final class LoadBalancer implements Runnable {
    final BlockingQueue<Packet> input = new ArrayBlockingQueue<>(PipelineEngine.QUEUE_CAPACITY);
    final AtomicLong dispatched = new AtomicLong();

    private final List<FastPath> fastPaths;
    private final int lbCount;

    LoadBalancer(List<FastPath> fastPaths, int lbCount) {
        this.fastPaths = fastPaths;
        this.lbCount = lbCount;
    }

    @Override
    public void run() {
        try {
            while (true) {
                Packet pkt = input.take();
                if (pkt == Packet.POISON) {
                    for (FastPath fp : fastPaths) fp.input.put(Packet.POISON);
                    return;
                }
                // The reader already used (hash % lbCount) to pick this LB, so divide first
                // to get an independent choice of fast path.
                int idx = (pkt.tuple().flowHash() / lbCount) % fastPaths.size();
                fastPaths.get(idx).input.put(pkt);
                dispatched.incrementAndGet();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
