package org.nexxus.protocol;

public final class VaultFile {
    public final String id;
    public final String name;
    public final int size;
    public final String hash;
    public final int chunks;
    public final long at;
    public final String from;

    public VaultFile(String id, String name, int size, String hash, int chunks, long at, String from) {
        this.id = id;
        this.name = name;
        this.size = size;
        this.hash = hash;
        this.chunks = chunks;
        this.at = at;
        this.from = from;
    }
}
