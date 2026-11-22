package com.dpi.pcap;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

/** Writes a .pcap file (little-endian, the format Wireshark expects). */
public final class PcapWriter implements AutoCloseable {
    private final OutputStream out;

    public PcapWriter(Path file, PcapGlobalHeader h) throws IOException {
        out = new BufferedOutputStream(Files.newOutputStream(file), 1 << 16);
        ByteBuffer b = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(0xa1b2c3d4)
         .putShort((short) h.versionMajor()).putShort((short) h.versionMinor())
         .putInt(h.thiszone()).putInt(h.sigfigs())
         .putInt((int) h.snaplen()).putInt((int) h.network());
        out.write(b.array());
    }

    public void write(long tsSec, long tsUsec, byte[] data) throws IOException {
        ByteBuffer b = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt((int) tsSec).putInt((int) tsUsec).putInt(data.length).putInt(data.length);
        out.write(b.array());
        out.write(data);
    }

    @Override
    public void close() throws IOException {
        out.close();
    }
}
