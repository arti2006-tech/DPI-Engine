package com.dpi.rules;

import com.dpi.model.AppType;
import com.dpi.model.Ip;

import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.List;

/** Blocking rules (IP, application, domain). Safe to call from many fast-path threads at once. */
public final class RuleManager {
    private final Set<Integer> blockedIps = ConcurrentHashMap.newKeySet();
    private final Set<AppType> blockedApps = ConcurrentHashMap.newKeySet();
    private final List<String> blockedDomains = new CopyOnWriteArrayList<>();

    public void blockIp(String ip) {
        blockedIps.add(Ip.parse(ip));
        System.out.println("[Rules] Blocked IP: " + ip);
    }

    public void blockApp(String name) {
        AppType.fromLabel(name).ifPresentOrElse(app -> {
            blockedApps.add(app);
            System.out.println("[Rules] Blocked app: " + app);
        }, () -> System.err.println("[Rules] Unknown app: " + name));
    }

    /** Substring match, e.g. "tiktok" blocks any SNI containing "tiktok". */
    public void blockDomain(String domain) {
        blockedDomains.add(domain.toLowerCase(Locale.ROOT));
        System.out.println("[Rules] Blocked domain: " + domain);
    }

    public boolean isBlocked(int srcIp, AppType app, String sni) {
        if (blockedIps.contains(srcIp)) return true;
        if (blockedApps.contains(app)) return true;
        if (!sni.isEmpty()) {
            String lower = sni.toLowerCase(Locale.ROOT);
            for (String dom : blockedDomains) {
                if (lower.contains(dom)) return true;
            }
        }
        return false;
    }
}
