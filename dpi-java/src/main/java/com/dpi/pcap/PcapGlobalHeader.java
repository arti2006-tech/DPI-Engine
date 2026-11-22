package com.dpi.pcap;

/** The 24-byte header at the start of every .pcap file. */
public record PcapGlobalHeader(int versionMajor, int versionMinor, int thiszone, int sigfigs,
                               long snaplen, long network) {}
