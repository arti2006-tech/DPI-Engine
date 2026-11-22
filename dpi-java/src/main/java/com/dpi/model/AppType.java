package com.dpi.model;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

/** Application classification (types.h / types.cpp in the C++ version). */
public enum AppType {
    UNKNOWN("Unknown"), HTTP("HTTP"), HTTPS("HTTPS"), DNS("DNS"), TLS("TLS"), QUIC("QUIC"),
    GOOGLE("Google"), FACEBOOK("Facebook"), YOUTUBE("YouTube"), TWITTER("Twitter/X"),
    INSTAGRAM("Instagram"), NETFLIX("Netflix"), AMAZON("Amazon"), MICROSOFT("Microsoft"),
    APPLE("Apple"), WHATSAPP("WhatsApp"), TELEGRAM("Telegram"), TIKTOK("TikTok"),
    SPOTIFY("Spotify"), ZOOM("Zoom"), DISCORD("Discord"), GITHUB("GitHub"), CLOUDFLARE("Cloudflare");

    private final String label;

    AppType(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    @Override
    public String toString() {
        return label;
    }

    /** Looks an app up by its display name ("YouTube", "Twitter/X", ...), ignoring case. */
    public static Optional<AppType> fromLabel(String name) {
        for (AppType t : values()) {
            if (t.label.equalsIgnoreCase(name.trim())) return Optional.of(t);
        }
        return Optional.empty();
    }

    // ---- SNI / hostname -> application (order matters: first match wins) ----

    private record Rule(AppType app, String... needles) {}

    private static final List<Rule> RULES = List.of(
        new Rule(GOOGLE, "google", "gstatic", "googleapis", "ggpht", "gvt1"),
        new Rule(YOUTUBE, "youtube", "ytimg", "youtu.be", "yt3.ggpht"),
        new Rule(FACEBOOK, "facebook", "fbcdn", "fb.com", "fbsbx", "meta.com"),
        new Rule(INSTAGRAM, "instagram", "cdninstagram"),
        new Rule(WHATSAPP, "whatsapp", "wa.me"),
        new Rule(TWITTER, "twitter", "twimg", "x.com", "t.co"),
        new Rule(NETFLIX, "netflix", "nflxvideo", "nflximg"),
        new Rule(AMAZON, "amazon", "amazonaws", "cloudfront", "aws"),
        new Rule(MICROSOFT, "microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing"),
        new Rule(APPLE, "apple", "icloud", "mzstatic", "itunes"),
        new Rule(TELEGRAM, "telegram", "t.me"),
        new Rule(TIKTOK, "tiktok", "tiktokcdn", "musical.ly", "bytedance"),
        new Rule(SPOTIFY, "spotify", "scdn.co"),
        new Rule(ZOOM, "zoom"),
        new Rule(DISCORD, "discord", "discordapp"),
        new Rule(GITHUB, "github", "githubusercontent"),
        new Rule(CLOUDFLARE, "cloudflare", "cf-")
    );

    public static AppType fromSni(String sni) {
        if (sni == null || sni.isEmpty()) return UNKNOWN;
        String lower = sni.toLowerCase(Locale.ROOT);
        for (Rule r : RULES) {
            for (String needle : r.needles()) {
                if (matches(lower, needle)) return r.app();
            }
        }
        return HTTPS; // SNI present but not recognised
    }

    /**
     * Keywords without a dot ("google") match anywhere in the hostname.
     * Domain rules with a dot ("t.co", "x.com") must match a whole domain, otherwise
     * "www.microsoft.com" would match "t.co" and "www.netflix.com" would match "x.com"
     * (a bug in the original C++ code).
     */
    private static boolean matches(String host, String needle) {
        if (needle.indexOf('.') < 0) return host.contains(needle);
        return host.equals(needle) || host.endsWith("." + needle);
    }
}
