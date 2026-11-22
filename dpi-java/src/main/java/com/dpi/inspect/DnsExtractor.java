package com.dpi.inspect;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/** Reads the queried domain name from a DNS request (not used for blocking, handy for logging). */
public final class DnsExtractor {
    private DnsExtractor() {}

    public static boolean isQuery(byte[] d, int base, int length) {
        if (length < 12) return false;
        if ((d[base + 2] & 0x80) != 0) return false;                       // QR bit set = response
        int qdCount = ((d[base + 4] & 0xFF) << 8) | (d[base + 5] & 0xFF);
        return qdCount > 0;
    }

    public static Optional<String> extractQuery(byte[] d, int base, int length) {
        if (!isQuery(d, base, length)) return Optional.empty();

        StringBuilder domain = new StringBuilder();
        int off = 12;
        while (off < length) {
            int labelLen = d[base + off] & 0xFF;
            if (labelLen == 0 || labelLen > 63) break;     // end of name, or compression pointer
            off++;
            if (off + labelLen > length) break;
            if (domain.length() > 0) domain.append('.');
            domain.append(new String(d, base + off, labelLen, StandardCharsets.US_ASCII));
            off += labelLen;
        }
        return domain.length() == 0 ? Optional.empty() : Optional.of(domain.toString());
    }
}
