package com.dpi.model;

/** Per-connection state. Each flow is owned by exactly one thread, so no locking is needed. */
public final class Flow {
    public final FiveTuple tuple;
    public AppType appType = AppType.UNKNOWN;
    public String sni = "";
    public long packets;
    public long bytes;
    public boolean blocked;
    public boolean classified;

    public Flow(FiveTuple tuple) {
        this.tuple = tuple;
    }
}
