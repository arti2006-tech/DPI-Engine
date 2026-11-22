package com.dpi.inspect;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the Server Name Indication from a TLS Client Hello.
 * Every read is bounds-checked: unlike C++, a bad offset throws instead of silently reading garbage.
 */
public final class SniExtractor {
    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    private SniExtractor() {}

    public static boolean isClientHello(byte[] d, int base, int length) {
        if (length < 9) return false;
        if (u8(d, base) != CONTENT_TYPE_HANDSHAKE) return false;
        int version = u16(d, base + 1);
        if (version < 0x0300 || version > 0x0304) return false;
        int recordLength = u16(d, base + 3);
        if (recordLength > length - 5) return false;
        return u8(d, base + 5) == HANDSHAKE_CLIENT_HELLO;
    }

    /** @param d packet bytes, @param base where the TCP payload starts, @param length payload length */
    public static Optional<String> extract(byte[] d, int base, int length) {
        try {
            if (!isClientHello(d, base, length)) return Optional.empty();

            int off = 5;        // skip TLS record header
            off += 4;           // handshake header (type + 3-byte length)
            off += 2;           // client version
            off += 32;          // random

            if (off >= length) return Optional.empty();
            off += 1 + u8(d, base + off);                       // session id

            if (off + 2 > length) return Optional.empty();
            off += 2 + u16(d, base + off);                      // cipher suites

            if (off >= length) return Optional.empty();
            off += 1 + u8(d, base + off);                       // compression methods

            if (off + 2 > length) return Optional.empty();
            int extensionsLength = u16(d, base + off);
            off += 2;

            int extensionsEnd = Math.min(off + extensionsLength, length);   // tolerate truncation

            while (off + 4 <= extensionsEnd) {
                int type = u16(d, base + off);
                int extLen = u16(d, base + off + 2);
                off += 4;
                if (off + extLen > extensionsEnd) break;

                if (type == EXTENSION_SNI) {
                    if (extLen < 5) break;
                    int listLen = u16(d, base + off);
                    if (listLen < 3) break;
                    int sniType = u8(d, base + off + 2);
                    int sniLen = u16(d, base + off + 3);
                    if (sniType != SNI_TYPE_HOSTNAME) break;
                    if (sniLen > extLen - 5) break;
                    return Optional.of(new String(d, base + off + 5, sniLen, StandardCharsets.US_ASCII));
                }
                off += extLen;
            }
        } catch (IndexOutOfBoundsException truncated) {
            // malformed / truncated packet: treat as "no SNI"
        }
        return Optional.empty();
    }

    private static int u8(byte[] d, int i) { return d[i] & 0xFF; }
    private static int u16(byte[] d, int i) { return ((d[i] & 0xFF) << 8) | (d[i + 1] & 0xFF); }
}
