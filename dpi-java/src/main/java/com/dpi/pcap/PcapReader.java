package com.dpi.pcap;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

/** Reads classic .pcap files (either byte order). */
public final class PcapReader implements AutoCloseable {
    private static final int MAGIC = 0xa1b2c3d4;
    private static final int MAGIC_SWAPPED = 0xd4c3b2a1;

    private final InputStream in;
    private final ByteOrder order;
    private final PcapGlobalHeader header;

    public PcapReader(Path file) throws IOException {
        in = new BufferedInputStream(Files.newInputStream(file), 1 << 16);
        try {
            byte[] gh = in.readNBytes(24);
            if (gh.length < 24) throw new IOException("Could not read PCAP global header");

            int magic = ByteBuffer.wrap(gh).order(ByteOrder.LITTLE_ENDIAN).getInt(0);
            if (magic == MAGIC) order = ByteOrder.LITTLE_ENDIAN;
            else if (magic == MAGIC_SWAPPED) order = ByteOrder.BIG_ENDIAN;
            else throw new IOException("Invalid PCAP magic number: 0x" + Integer.toHexString(magic));

            ByteBuffer b = ByteBuffer.wrap(gh).order(order);
            header = new PcapGlobalHeader(
                b.getShort(4) & 0xFFFF, b.getShort(6) & 0xFFFF, b.getInt(8), b.getInt(12),
                b.getInt(16) & 0xFFFFFFFFL, b.getInt(20) & 0xFFFFFFFFL);
        } catch (IOException | RuntimeException e) {
            in.close();
            throw e;
        }

        System.out.println("Opened PCAP file: " + file);
        System.out.println("  Version: " + header.versionMajor() + "." + header.versionMinor());
        System.out.println("  Snaplen: " + header.snaplen() + " bytes");
        System.out.println("  Link type: " + header.network() + (header.network() == 1 ? " (Ethernet)" : ""));
    }

    public PcapGlobalHeader header() {
        return header;
    }

    /** Returns the next packet, or null at end of file (or on a corrupt record). */
    public RawPacket next() throws IOException {
        byte[] ph = in.readNBytes(16);
        if (ph.length < 16) return null;

        ByteBuffer b = ByteBuffer.wrap(ph).order(order);
        long tsSec = b.getInt(0) & 0xFFFFFFFFL;
        long tsUsec = b.getInt(4) & 0xFFFFFFFFL;
        long inclLen = b.getInt(8) & 0xFFFFFFFFL;
        long origLen = b.getInt(12) & 0xFFFFFFFFL;

        if (inclLen > 65535 || (header.snaplen() > 0 && inclLen > header.snaplen())) {
            System.err.println("Error: Invalid packet length: " + inclLen);
            return null;
        }
        byte[] data = in.readNBytes((int) inclLen);
        if (data.length < inclLen) {
            System.err.println("Error: Could not read packet data");
            return null;
        }
        return new RawPacket(tsSec, tsUsec, origLen, data);
    }

    @Override
    public void close() throws IOException {
        in.close();
    }
}
