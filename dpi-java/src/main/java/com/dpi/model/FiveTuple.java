package com.dpi.model;

/** Uniquely identifies a flow. A record gives us equals()/hashCode(), so it works as a HashMap key. */
public record FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {

    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    /** Non-negative, well-mixed hash used to pick load-balancer / fast-path threads. */
    public int flowHash() {
        int h = 0;
        for (int v : new int[] {srcIp, dstIp, srcPort, dstPort, protocol}) {
            h ^= v + 0x9e3779b9 + (h << 6) + (h >>> 2);
        }
        h ^= h >>> 16;
        h *= 0x85ebca6b;
        h ^= h >>> 13;
        return h & 0x7fffffff;
    }

    @Override
    public String toString() {
        String proto = protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?";
        return Ip.format(srcIp) + ":" + srcPort + " -> " + Ip.format(dstIp) + ":" + dstPort + " (" + proto + ")";
    }
}
