package com.dpi.engine;

import com.dpi.model.AppType;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

/** Thread-safe counters shared by all threads. */
public final class Stats {
    public final AtomicLong totalPackets = new AtomicLong();
    public final AtomicLong totalBytes = new AtomicLong();
    public final AtomicLong forwarded = new AtomicLong();
    public final AtomicLong dropped = new AtomicLong();
    public final AtomicLong tcpPackets = new AtomicLong();
    public final AtomicLong udpPackets = new AtomicLong();

    private final ConcurrentHashMap<AppType, LongAdder> appCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AppType> detectedSnis = new ConcurrentHashMap<>();

    public void recordApp(AppType app, String sni) {
        appCounts.computeIfAbsent(app, k -> new LongAdder()).increment();
        if (!sni.isEmpty()) detectedSnis.put(sni, app);
    }

    public Map<AppType, Long> appCounts() {
        Map<AppType, Long> copy = new HashMap<>();
        appCounts.forEach((k, v) -> copy.put(k, v.sum()));
        return copy;
    }

    public Map<String, AppType> detectedSnis() {
        return new HashMap<>(detectedSnis);
    }
}
