package com.dpi.engine;

import com.dpi.model.AppType;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Console banner and processing report. */
public final class Report {
    private static final int W = 62;

    private Report() {}

    public static void banner(String title, String... extraRows) {
        System.out.println();
        System.out.println("╔" + "═".repeat(W) + "╗");
        System.out.println(center(title));
        if (extraRows.length > 0) {
            System.out.println("╠" + "═".repeat(W) + "╣");
            for (String r : extraRows) System.out.println(row(r));
        }
        System.out.println("╚" + "═".repeat(W) + "╝");
        System.out.println();
    }

    /** @param activeFlows pass -1 to hide the line; @param threadLines null to hide the section */
    public static void print(Stats s, long activeFlows, List<String> threadLines) {
        System.out.println();
        System.out.println("╔" + "═".repeat(W) + "╗");
        System.out.println(center("PROCESSING REPORT"));
        System.out.println(sep());
        System.out.println(row(String.format("Total Packets:  %12d", s.totalPackets.get())));
        System.out.println(row(String.format("Total Bytes:    %12d", s.totalBytes.get())));
        System.out.println(row(String.format("TCP Packets:    %12d", s.tcpPackets.get())));
        System.out.println(row(String.format("UDP Packets:    %12d", s.udpPackets.get())));
        System.out.println(sep());
        System.out.println(row(String.format("Forwarded:      %12d", s.forwarded.get())));
        System.out.println(row(String.format("Dropped:        %12d", s.dropped.get())));
        if (activeFlows >= 0) System.out.println(row(String.format("Active Flows:   %12d", activeFlows)));

        if (threadLines != null) {
            System.out.println(sep());
            System.out.println(row("THREAD STATISTICS"));
            for (String l : threadLines) System.out.println(row("  " + l));
        }

        System.out.println(sep());
        System.out.println(center("APPLICATION BREAKDOWN"));
        System.out.println(sep());

        List<Map.Entry<AppType, Long>> sorted = new ArrayList<>(s.appCounts().entrySet());
        sorted.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));
        long total = s.totalPackets.get();
        for (Map.Entry<AppType, Long> e : sorted) {
            double pct = total > 0 ? 100.0 * e.getValue() / total : 0;
            String bar = "#".repeat((int) (pct / 5));
            System.out.println(row(String.format("%-15s%8d %5.1f%% %-20s", e.getKey().label(), e.getValue(), pct, bar)));
        }
        System.out.println("╚" + "═".repeat(W) + "╝");

        Map<String, AppType> snis = s.detectedSnis();
        if (!snis.isEmpty()) {
            System.out.println("\n[Detected Domains/SNIs]");
            snis.entrySet().stream().sorted(Map.Entry.comparingByKey())
                .forEach(e -> System.out.println("  - " + e.getKey() + " -> " + e.getValue()));
        }
    }

    private static String sep() { return "╠" + "═".repeat(W) + "╣"; }

    private static String row(String text) {
        return "║ " + String.format("%-" + (W - 1) + "s", text) + "║";
    }

    private static String center(String text) {
        int pad = Math.max(0, W - text.length());
        int left = pad / 2;
        return "║" + " ".repeat(left) + text + " ".repeat(pad - left) + "║";
    }
}
