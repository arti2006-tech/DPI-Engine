package com.dpi;

import com.dpi.engine.PipelineEngine;
import com.dpi.engine.Report;
import com.dpi.engine.SimpleEngine;
import com.dpi.rules.RuleManager;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class Main {
    private Main() {}

    public static void main(String[] args) {
        // Make the box-drawing characters render correctly on any console (e.g. Windows).
        System.setOut(new PrintStream(System.out, true, StandardCharsets.UTF_8));

        if (args.length < 2) {
            usage();
            System.exit(1);
        }

        Path input = Path.of(args[0]);
        Path output = Path.of(args[1]);
        List<String> blockIps = new ArrayList<>(), blockApps = new ArrayList<>(), blockDomains = new ArrayList<>();
        int lbs = 2, fps = 2;
        boolean single = false;

        try {
            for (int i = 2; i < args.length; i++) {
                switch (args[i]) {
                    case "--block-ip" -> blockIps.add(value(args, ++i));
                    case "--block-app" -> blockApps.add(value(args, ++i));
                    case "--block-domain" -> blockDomains.add(value(args, ++i));
                    case "--lbs" -> lbs = Integer.parseInt(value(args, ++i));
                    case "--fps" -> fps = Integer.parseInt(value(args, ++i));
                    case "--single" -> single = true;
                    default -> System.err.println("Warning: ignoring unknown option " + args[i]);
                }
            }

            if (single) {
                Report.banner("DPI ENGINE v1.0 (Single-threaded)");
            } else {
                Report.banner("DPI ENGINE v2.0 (Multi-threaded)",
                    String.format("Load Balancers: %2d    FPs per LB: %2d    Total FPs: %2d", lbs, fps, lbs * fps));
            }

            RuleManager rules = new RuleManager();
            blockIps.forEach(rules::blockIp);
            blockApps.forEach(rules::blockApp);
            blockDomains.forEach(rules::blockDomain);

            if (single) new SimpleEngine(rules).process(input, output);
            else new PipelineEngine(new PipelineEngine.Config(lbs, fps), rules).process(input, output);

            System.out.println("\nOutput written to: " + output);
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Error: " + (e.getMessage() != null ? e.getMessage() : e));
            System.exit(1);
        }
    }

    private static String value(String[] args, int i) {
        if (i >= args.length) throw new IllegalArgumentException("Missing value for " + args[i - 1]);
        return args[i];
    }

    private static void usage() {
        System.out.println("""

            DPI Engine - Deep Packet Inspection (Java)
            ==========================================

            Usage: java -jar dpi-engine.jar <input.pcap> <output.pcap> [options]

            Options:
              --block-ip <ip>        Block traffic from source IP
              --block-app <app>      Block application (YouTube, Facebook, TikTok, ...)
              --block-domain <dom>   Block domain (substring match)
              --lbs <n>              Load balancer threads (default: 2)
              --fps <n>              Fast-path threads per LB (default: 2)
              --single               Use the simple single-threaded engine

            Example:
              java -jar dpi-engine.jar capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
            """);
    }
}
