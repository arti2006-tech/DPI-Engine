package com.dpi.pcap;

/** One captured packet: PCAP record header fields plus the raw bytes. */
public record RawPacket(long tsSec, long tsUsec, long origLen, byte[] data) {}
