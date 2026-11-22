package com.dpi.parser;

import com.dpi.model.Ip;

/** Human-readable view of a raw packet's Ethernet / IPv4 / TCP / UDP headers. */
public final class ParsedPacket {
    public long tsSec, tsUsec;

    public String srcMac, destMac;
    public int etherType;

    public boolean hasIp;
    public int ipVersion;
    public int srcIp, destIp;   // big-endian packed
    public int protocol;        // TCP=6, UDP=17, ICMP=1
    public int ttl;

    public boolean hasTcp, hasUdp;
    public int srcPort, destPort;

    public int tcpFlags;
    public long seqNumber, ackNumber;

    /** Where the application payload starts inside the raw packet bytes. */
    public int payloadOffset;
    public int payloadLength;

    public String srcIpString() { return Ip.format(srcIp); }
    public String destIpString() { return Ip.format(destIp); }
}
