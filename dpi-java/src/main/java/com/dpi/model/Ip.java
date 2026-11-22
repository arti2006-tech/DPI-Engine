package com.dpi.model;

/** IPv4 helpers. Addresses are stored as a big-endian int (192.168.1.1 -> 0xC0A80101). */
public final class Ip {
    private Ip() {}

    public static int parse(String s) {
        String[] parts = s.trim().split("\\.");
        if (parts.length != 4) throw new IllegalArgumentException("Invalid IPv4 address: " + s);
        int result = 0;
        for (String p : parts) {
            int octet = Integer.parseInt(p);
            if (octet < 0 || octet > 255) throw new IllegalArgumentException("Invalid IPv4 address: " + s);
            result = (result << 8) | octet;
        }
        return result;
    }

    public static String format(int ip) {
        return ((ip >>> 24) & 0xFF) + "." + ((ip >>> 16) & 0xFF) + "." + ((ip >>> 8) & 0xFF) + "." + (ip & 0xFF);
    }
}
