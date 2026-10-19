package org.nexxus.protocol;

public final class ChatLine {
    public final String id;
    public final String fp;
    public final boolean fromMe;
    public final String text;
    public final long at;

    public ChatLine(String id, String fp, boolean fromMe, String text, long at) {
        this.id = id;
        this.fp = fp;
        this.fromMe = fromMe;
        this.text = text;
        this.at = at;
    }
}
