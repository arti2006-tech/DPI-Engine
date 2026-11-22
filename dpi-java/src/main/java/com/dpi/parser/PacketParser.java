package com.dpi.parser;

import com.dpi.pcap.RawPacket;

/** Parses Ethernet -> IPv4 -> TCP/UDP. Java has no unsigned types, so every byte is masked with 0xFF. */
public final class PacketParser {
    public static final int ETHER_IPV4 = 0x0800;
    public static final int PROTO_ICMP = 1, PROTO_TCP = 6, PROTO_UDP = 17;

    private PacketParser() {}

    /** Returns null if the packet is truncated or malformed. */
    public static ParsedPacket parse(RawPacket raw) {
        byte[] d = raw.data();
        int len = d.length;

        ParsedPacket p = new ParsedPacket();
        p.tsSec = raw.tsSec();
        p.tsUsec = raw.tsUsec();

        // ---- Ethernet (14 bytes) ----
        if (len < 14) return null;
        p.destMac = mac(d, 0);
        p.srcMac = mac(d, 6);
        p.etherType = u16(d, 12);
        int off = 14;

        if (p.etherType == ETHER_IPV4) {
            // ---- IPv4 (20+ bytes) ----
            if (len < off + 20) return null;
            int versionIhl = d[off] & 0xFF;
            p.ipVersion = versionIhl >> 4;
            if (p.ipVersion != 4) return null;
            int ipHeaderLen = (versionIhl & 0x0F) * 4;
            if (ipHeaderLen < 20 || len < off + ipHeaderLen) return null;

            p.ttl = d[off + 8] & 0xFF;
            p.protocol = d[off + 9] & 0xFF;
            p.srcIp = u32(d, off + 12);
            p.destIp = u32(d, off + 16);
            p.hasIp = true;
            off += ipHeaderLen;

            if (p.protocol == PROTO_TCP) {
                // ---- TCP (20+ bytes) ----
                if (len < off + 20) return null;
                p.srcPort = u16(d, off);
                p.destPort = u16(d, off + 2);
                p.seqNumber = u32(d, off + 4) & 0xFFFFFFFFL;
                p.ackNumber = u32(d, off + 8) & 0xFFFFFFFFL;
                int tcpHeaderLen = ((d[off + 12] >> 4) & 0x0F) * 4;
                p.tcpFlags = d[off + 13] & 0xFF;
                if (tcpHeaderLen < 20 || len < off + tcpHeaderLen) return null;
                p.hasTcp = true;
                off += tcpHeaderLen;
            } else if (p.protocol == PROTO_UDP) {
                // ---- UDP (8 bytes) ----
                if (len < off + 8) return null;
                p.srcPort = u16(d, off);
                p.destPort = u16(d, off + 2);
                p.hasUdp = true;
                off += 8;
            }
        }

        p.payloadOffset = off;
        p.payloadLength = off < len ? len - off : 0;
        return p;
    }

    /** Big-endian unsigned 16-bit read (replaces ntohs). */
    static int u16(byte[] d, int i) {
        return ((d[i] & 0xFF) << 8) | (d[i + 1] & 0xFF);
    }

    /** Big-endian 32-bit read (replaces ntohl). Mask with 0xFFFFFFFFL if you need it unsigned. */
    static int u32(byte[] d, int i) {
        return ((d[i] & 0xFF) << 24) | ((d[i + 1] & 0xFF) << 16) | ((d[i + 2] & 0xFF) << 8) | (d[i + 3] & 0xFF);
    }

    private static String mac(byte[] d, int i) {
        StringBuilder sb = new StringBuilder(17);
        for (int k = 0; k < 6; k++) {
            if (k > 0) sb.append(':');
            sb.append(String.format("%02x", d[i + k] & 0xFF));
        }
        return sb.toString();
    }
}
