package org.nexxus.protocol;

public final class Contact {
    public final String fingerprint;
    public final String pubHex;
    public final String host;
    public final int port;
    public final String name;
    public final long addedAt;
    public volatile boolean online;

    public Contact(String fingerprint, String pubHex, String host, int port, String name) {
        this(fingerprint, pubHex, host, port, name, System.currentTimeMillis());
    }

    public Contact(String fingerprint, String pubHex, String host, int port, String name, long addedAt) {
        this.fingerprint = fingerprint;
        this.pubHex = pubHex;
        this.host = host;
        this.port = port;
        this.name = name == null || name.isEmpty() ? fingerprint : name;
        this.addedAt = addedAt;
    }

    public Contact withName(String next) {
        Contact c = new Contact(fingerprint, pubHex, host, port, next, addedAt);
        c.online = online;
        return c;
    }
}
