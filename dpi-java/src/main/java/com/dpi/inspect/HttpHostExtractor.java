package com.dpi.inspect;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/** Pulls the Host header out of a plain-text HTTP request. */
public final class HttpHostExtractor {
    private static final String[] METHODS = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};

    private HttpHostExtractor() {}

    public static boolean isHttpRequest(byte[] d, int base, int length) {
        if (length < 4) return false;
        String start = new String(d, base, 4, StandardCharsets.ISO_8859_1);
        for (String m : METHODS) {
            if (start.equals(m)) return true;
        }
        return false;
    }

    public static Optional<String> extract(byte[] d, int base, int length) {
        if (!isHttpRequest(d, base, length)) return Optional.empty();

        for (int i = 0; i + 6 < length; i++) {
            if (lower(d[base + i]) == 'h' && lower(d[base + i + 1]) == 'o'
                    && lower(d[base + i + 2]) == 's' && lower(d[base + i + 3]) == 't'
                    && d[base + i + 4] == ':') {

                int start = i + 5;
                while (start < length && (d[base + start] == ' ' || d[base + start] == '\t')) start++;
                int end = start;
                while (end < length && d[base + end] != '\r' && d[base + end] != '\n') end++;

                if (end > start) {
                    String host = new String(d, base + start, end - start, StandardCharsets.ISO_8859_1);
                    int colon = host.indexOf(':');          // strip ":port"
                    if (colon >= 0) host = host.substring(0, colon);
                    return Optional.of(host);
                }
            }
        }
        return Optional.empty();
    }

    private static int lower(byte b) {
        return Character.toLowerCase(b & 0xFF);
    }
}
