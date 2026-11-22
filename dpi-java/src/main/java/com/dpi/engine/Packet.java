package com.dpi.engine;

import com.dpi.model.FiveTuple;

/** Self-contained packet passed between threads through the queues. */
record Packet(int id, long tsSec, long tsUsec, FiveTuple tuple, byte[] data,
              int tcpFlags, int payloadOffset, int payloadLength) {

    /** Sentinel that tells a consumer thread "no more packets are coming" (replaces the C++ running_ flag). */
    static final Packet POISON = new Packet(-1, 0, 0, null, new byte[0], 0, 0, 0);
}
