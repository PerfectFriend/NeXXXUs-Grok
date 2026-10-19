package org.nexxus.protocol;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** TCP mesh compatible with linux-node 0.1.2. */
public final class NodeSession {
    public static final int CHUNK = 16 * 1024;
    private static final int MAX_FRAME = 8 * 1024 * 1024;

    public final Identity identity;
    private final File dataDir;
    private final List<Contact> contacts = new ArrayList<Contact>();
    private final List<ChatLine> messages = new ArrayList<ChatLine>();
    private final List<VaultFile> files = new ArrayList<VaultFile>();
    private final List<String> log = new ArrayList<String>();
    private final Map<String, Link> links = new ConcurrentHashMap<String, Link>();
    private final Map<String, Incoming> incoming = new ConcurrentHashMap<String, Incoming>();
    private final List<Runnable> listeners = new ArrayList<Runnable>();

    private String bindHost = "0.0.0.0";
    private String advertise = "127.0.0.1";
    private String nodeName = "android";
    private int listenPort = 4377;
    private ServerSocket server;
    private Thread acceptThread;
    private Thread retryThread;
    private volatile boolean running;

    public NodeSession(Identity identity, File dataDir) {
        this.identity = identity;
        this.dataDir = dataDir;
        if (!dataDir.isDirectory() && !dataDir.mkdirs()) {
            throw new IllegalStateException("нет каталога " + dataDir);
        }
        load();
    }

    public synchronized void listen(String bindHost, int port, String advertiseHost, String name) throws IOException {
        this.bindHost = bindHost == null || bindHost.isEmpty() ? "0.0.0.0" : bindHost;
        this.listenPort = port;
        this.advertise = advertiseHost;
        this.nodeName = name == null || name.isEmpty() ? "android" : name;
        if (server != null && !server.isClosed() && server.getLocalPort() == port) return;
        if (server != null) {
            try { server.close(); } catch (IOException ignored) {}
            server = null;
        }
        ServerSocket ss = new ServerSocket();
        ss.setReuseAddress(true);
        ss.bind(new InetSocketAddress(this.bindHost, port));
        server = ss;
        running = true;
        log("Mesh слушает " + this.bindHost + ":" + port);
        acceptThread = new Thread(new Runnable() {
            @Override public void run() { acceptLoop(); }
        }, "nexxus-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
        if (retryThread == null || !retryThread.isAlive()) {
            retryThread = new Thread(new Runnable() {
                @Override public void run() { retryLoop(); }
            }, "nexxus-retry");
            retryThread.setDaemon(true);
            retryThread.start();
        }
        for (Contact c : snapshotContacts()) {
            dial(c);
        }
    }

    public synchronized String contactUri() {
        return Identity.formatContact(identity.fingerprint, identity.pubHex, advertise, listenPort);
    }

    public synchronized String advertiseHost() { return advertise; }
    public synchronized int port() { return listenPort; }
    public synchronized String name() { return nodeName; }

    public void addListener(Runnable r) {
        synchronized (listeners) { listeners.add(r); }
    }

    public synchronized Contact addContact(String uri) {
        Contact spec = Identity.parseContact(uri);
        if (spec.fingerprint.equals(identity.fingerprint)) {
            throw new IllegalArgumentException("Это ваш собственный контакт.");
        }
        Contact row = new Contact(spec.fingerprint, spec.pubHex, spec.host, spec.port, spec.fingerprint);
        upsert(row);
        saveContacts();
        emit();
        dial(row);
        return row;
    }

    public synchronized ChatLine sendChat(String fp, String text) {
        String trimmed = text == null ? "" : text.trim();
        if (trimmed.isEmpty()) throw new IllegalArgumentException("Пустое сообщение.");
        ChatLine msg = new ChatLine(UUID.randomUUID().toString(), fp, true, trimmed, System.currentTimeMillis());
        Map<String, Object> obj = new LinkedHashMap<String, Object>();
        obj.put("t", "chat");
        obj.put("id", msg.id);
        obj.put("text", trimmed);
        obj.put("ts", Long.valueOf(msg.at));
        send(fp, obj);
        messages.add(msg);
        trimMessages();
        saveMessages();
        emit();
        return msg;
    }

    public synchronized VaultFile storePlain(String name, byte[] bytes) {
        return storePlain(null, name, bytes, null);
    }

    public synchronized void sendFile(String fp, String id) {
        VaultFile rec = findFile(id);
        if (rec == null) throw new IllegalArgumentException("Файл не найден.");
        byte[] plain = loadPlain(id);
        Link link = links.get(fp);
        if (link == null || link.socket.isClosed()) throw new IllegalArgumentException("Нет канала с этим контактом.");
        Map<String, Object> meta = new LinkedHashMap<String, Object>();
        meta.put("t", "file_meta");
        meta.put("id", rec.id);
        meta.put("name", rec.name);
        meta.put("size", Integer.valueOf(rec.size));
        meta.put("hash", rec.hash);
        meta.put("chunks", Integer.valueOf(rec.chunks));
        send(fp, meta);
        for (int i = 0; i < rec.chunks; i++) {
            int from = i * CHUNK;
            int to = Math.min(plain.length, from + CHUNK);
            byte[] slice = new byte[to - from];
            System.arraycopy(plain, from, slice, 0, slice.length);
            byte[] packed = Aead.seal(link.key, slice);
            Map<String, Object> chunk = new LinkedHashMap<String, Object>();
            chunk.put("t", "chunk");
            chunk.put("id", rec.id);
            chunk.put("i", Integer.valueOf(i));
            chunk.put("data", B64.encode(packed));
            send(fp, chunk);
        }
        log(rec.name + ": " + rec.chunks + " чанков ушли на " + fp);
    }

    public synchronized byte[] loadPlain(String id) {
        VaultFile rec = findFile(id);
        if (rec == null) throw new IllegalArgumentException("Файл не найден.");
        try {
            int total = 0;
            byte[][] parts = new byte[rec.chunks][];
            for (int i = 0; i < rec.chunks; i++) {
                byte[] packed = readAll(chunkFile(id, i));
                parts[i] = Aead.open(identity.vaultKey, packed);
                total += parts[i].length;
            }
            byte[] out = new byte[total];
            int o = 0;
            for (byte[] p : parts) {
                System.arraycopy(p, 0, out, o, p.length);
                o += p.length;
            }
            return out;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public synchronized List<Contact> snapshotContacts() {
        List<Contact> copy = new ArrayList<Contact>();
        for (Contact c : contacts) {
            Contact n = new Contact(c.fingerprint, c.pubHex, c.host, c.port, c.name, c.addedAt);
            n.online = links.containsKey(c.fingerprint) && !links.get(c.fingerprint).socket.isClosed();
            copy.add(n);
        }
        return copy;
    }

    public synchronized List<ChatLine> snapshotMessages() {
        return new ArrayList<ChatLine>(messages);
    }

    public synchronized List<VaultFile> snapshotFiles() {
        return new ArrayList<VaultFile>(files);
    }

    public synchronized List<String> snapshotLog() {
        return new ArrayList<String>(log);
    }

    public void dial(Contact spec) {
        if (spec.fingerprint.equals(identity.fingerprint)) return;
        Link existing = links.get(spec.fingerprint);
        if (existing != null && !existing.socket.isClosed()) return;
        try {
            Socket socket = new Socket();
            socket.setKeepAlive(true);
            socket.setTcpNoDelay(true);
            socket.connect(new InetSocketAddress(spec.host, spec.port), 8000);
            startLink(socket, spec, false);
        } catch (IOException e) {
            log("Не удалось дозвониться до " + spec.host + ":" + spec.port + " — " + e.getMessage());
            markOffline(spec.fingerprint);
        }
    }

    public void stop() {
        running = false;
        try {
            if (server != null) server.close();
        } catch (IOException ignored) {}
        for (Link link : links.values()) {
            try { link.socket.close(); } catch (IOException ignored) {}
        }
        links.clear();
        if (acceptThread != null) acceptThread.interrupt();
        if (retryThread != null) retryThread.interrupt();
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket socket = server.accept();
                socket.setKeepAlive(true);
                socket.setTcpNoDelay(true);
                startLink(socket, null, true);
            } catch (IOException e) {
                if (running) log("accept: " + e.getMessage());
                break;
            }
        }
    }

    private void retryLoop() {
        while (running) {
            try {
                Thread.sleep(8000);
            } catch (InterruptedException e) {
                return;
            }
            for (Contact c : snapshotContacts()) {
                Link link = links.get(c.fingerprint);
                if (link == null || link.socket.isClosed()) dial(c);
                else {
                    try {
                        Map<String, Object> ping = new LinkedHashMap<String, Object>();
                        ping.put("t", "ping");
                        ping.put("ts", Long.valueOf(System.currentTimeMillis()));
                        send(c.fingerprint, ping);
                    } catch (RuntimeException ignored) {}
                }
            }
        }
    }

    private void startLink(final Socket socket, final Contact expected, final boolean inbound) {
        Thread t = new Thread(new Runnable() {
            @Override public void run() { readLoop(socket, expected, inbound); }
        }, "nexxus-link");
        t.setDaemon(true);
        t.start();
    }

    private void readLoop(Socket socket, Contact expected, boolean inbound) {
        Identity.Eph eph = Identity.generateEph();
        String fp = expected == null ? null : expected.fingerprint;
        byte[] key = null;
        boolean established = false;
        try {
            socket.setSoTimeout(12000);
            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            writeRaw(socket, Bytes.utf8(Json.stringify(identity.signHello(eph.pubHex, nodeName, advertise, listenPort))));
            while (running && !socket.isClosed()) {
                byte[] payload = readFrame(in);
                if (!established) {
                    Map<String, Object> hello = Json.obj(Bytes.utf8(payload));
                    Identity.verifyHello(hello);
                    String helloFp = Json.str(hello, "fp").toLowerCase();
                    String helloPub = Json.str(hello, "pub").toLowerCase();
                    if (helloFp.equals(identity.fingerprint)) {
                        log("Входящее соединение с собственным ключом — отброшено.");
                        socket.close();
                        return;
                    }
                    if (expected != null && (!expected.fingerprint.equals(helloFp) || !expected.pubHex.equals(helloPub))) {
                        log("Ключ не совпал с контактом " + expected.fingerprint + ".");
                        socket.close();
                        return;
                    }
                    key = Identity.sessionKey(
                            identity.xPriv, identity.xPub, eph.secret,
                            Hex.decode(helloPub), Hex.decode(Json.str(hello, "eph")),
                            !inbound);
                    fp = helloFp;
                    String host = Json.str(hello, "host");
                    int port = Json.num(hello, "port");
                    if (host.isEmpty() && expected != null) host = expected.host;
                    if (port == 0 && expected != null) port = expected.port;
                    String peerName = Json.str(hello, "name");
                    if (peerName.isEmpty()) peerName = helloFp;
                    Contact remote = new Contact(helloFp, helloPub, host, port, peerName);
                    Link prev = links.put(fp, new Link(socket, key, remote));
                    if (prev != null && prev.socket != socket) {
                        try { prev.socket.close(); } catch (IOException ignored) {}
                    }
                    established = true;
                    socket.setSoTimeout(0);
                    rememberPeer(remote, true);
                    log("Канал с " + peerName + " (" + fp + ") установлен. Сессия X25519 4DH.");
                } else {
                    byte[] plain = Aead.open(key, payload);
                    Map<String, Object> obj = Json.obj(Bytes.utf8(plain));
                    onPacket(fp, obj, key);
                }
            }
        } catch (Exception e) {
            if (running) log("Канал закрыт: " + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
            if (fp != null) {
                Link cur = links.get(fp);
                if (cur != null && cur.socket == socket) links.remove(fp);
                markOffline(fp);
            }
        }
    }

    private void onPacket(String fp, Map<String, Object> obj, byte[] key) {
        String t = Json.str(obj, "t");
        if ("chat".equals(t)) {
            synchronized (this) {
                ChatLine line = new ChatLine(Json.str(obj, "id"), fp, false, Json.str(obj, "text"),
                        obj.get("ts") instanceof Number ? ((Number) obj.get("ts")).longValue() : System.currentTimeMillis());
                messages.add(line);
                trimMessages();
                saveMessages();
                emit();
            }
        } else if ("file_meta".equals(t)) {
            int chunks = Json.num(obj, "chunks");
            String id = Json.str(obj, "id");
            if (id.isEmpty() || chunks < 1 || chunks > 4096) return;
            incoming.put(id, new Incoming(id, safeName(Json.str(obj, "name")), chunks, fp));
            log("Входящий файл " + safeName(Json.str(obj, "name")) + " (" + chunks + " чанков) от " + fp);
        } else if ("chunk".equals(t)) {
            receiveChunk(fp, obj, key);
        } else if ("ping".equals(t)) {
            Map<String, Object> pong = new LinkedHashMap<String, Object>();
            pong.put("t", "pong");
            pong.put("ts", Long.valueOf(System.currentTimeMillis()));
            try { send(fp, pong); } catch (RuntimeException ignored) {}
        }
    }

    private void receiveChunk(String fp, Map<String, Object> obj, byte[] key) {
        Incoming meta = incoming.get(Json.str(obj, "id"));
        if (meta == null) return;
        int i = Json.num(obj, "i");
        if (i < 0 || i >= meta.chunks) return;
        String data = Json.str(obj, "data");
        if (data.length() > 120000) return;
        byte[] raw;
        try {
            raw = Aead.open(key, B64.decode(data));
        } catch (RuntimeException e) {
            log("Чанк отклонён: " + e.getMessage());
            return;
        }
        if (raw.length > CHUNK + 64) return;
        synchronized (meta) {
            meta.bufs[i] = raw;
            int got = 0;
            int total = 0;
            for (byte[] b : meta.bufs) {
                if (b != null) { got++; total += b.length; }
            }
            if (got < meta.chunks) return;
            byte[] plain = new byte[total];
            int o = 0;
            for (byte[] b : meta.bufs) {
                System.arraycopy(b, 0, plain, o, b.length);
                o += b.length;
            }
            incoming.remove(meta.id);
            storePlain(meta.id, meta.name, plain, fp);
            log("Файл " + meta.name + " принят и записан в сейф.");
        }
    }

    private synchronized VaultFile storePlain(String id, String name, byte[] bytes, String from) {
        String fileId = (id == null || id.isEmpty() ? UUID.randomUUID().toString() : id).replaceAll("[^a-zA-Z0-9._-]", "");
        if (fileId.length() > 80) fileId = fileId.substring(0, 80);
        if (fileId.isEmpty()) fileId = UUID.randomUUID().toString();
        int chunks = Math.max(1, (bytes.length + CHUNK - 1) / CHUNK);
        File dir = new File(new File(dataDir, "vault"), fileId);
        if (!dir.isDirectory() && !dir.mkdirs()) throw new IllegalStateException("сейф");
        try {
            for (int i = 0; i < chunks; i++) {
                int a = i * CHUNK;
                int b = Math.min(bytes.length, a + CHUNK);
                byte[] slice = new byte[b - a];
                System.arraycopy(bytes, a, slice, 0, slice.length);
                writeAll(chunkFile(fileId, i), Aead.seal(identity.vaultKey, slice));
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        VaultFile rec = new VaultFile(fileId, safeName(name), bytes.length, sha256(bytes), chunks, System.currentTimeMillis(), from);
        Iterator<VaultFile> it = files.iterator();
        while (it.hasNext()) if (it.next().id.equals(fileId)) it.remove();
        files.add(0, rec);
        saveFiles();
        emit();
        return rec;
    }

    private void send(String fp, Map<String, Object> obj) {
        Link link = links.get(fp);
        if (link == null || link.socket.isClosed()) throw new IllegalArgumentException("Нет живого канала. Добавьте контакт и дождитесь связи.");
        try {
            writeRaw(link.socket, Aead.seal(link.key, Bytes.utf8(Json.stringify(obj))));
        } catch (IOException e) {
            throw new IllegalStateException(e.getMessage());
        }
    }

    private static void writeRaw(Socket socket, byte[] payload) throws IOException {
        synchronized (socket) {
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            out.writeInt(payload.length);
            out.write(payload);
            out.flush();
        }
    }

    private static byte[] readFrame(DataInputStream in) throws IOException {
        int n = in.readInt();
        if (n < 0 || n > MAX_FRAME) throw new IOException("frame too large");
        byte[] payload = new byte[n];
        in.readFully(payload);
        return payload;
    }

    private synchronized void rememberPeer(Contact remote, boolean online) {
        remote.online = online;
        boolean found = false;
        for (int i = 0; i < contacts.size(); i++) {
            if (contacts.get(i).fingerprint.equals(remote.fingerprint)) {
                contacts.set(i, remote);
                found = true;
                break;
            }
        }
        if (!found) contacts.add(0, remote);
        saveContacts();
        emit();
    }

    private synchronized void markOffline(String fp) {
        emit();
    }

    private synchronized void upsert(Contact row) {
        for (int i = 0; i < contacts.size(); i++) {
            if (contacts.get(i).fingerprint.equals(row.fingerprint)) {
                contacts.set(i, row);
                return;
            }
        }
        contacts.add(0, row);
    }

    private void trimMessages() {
        while (messages.size() > 400) messages.remove(0);
    }

    private VaultFile findFile(String id) {
        for (VaultFile f : files) if (f.id.equals(id)) return f;
        return null;
    }

    private File chunkFile(String id, int i) {
        return new File(new File(new File(dataDir, "vault"), id), String.format("c-%05d.bin", i));
    }

    private void log(String text) {
        synchronized (this) {
            log.add(0, text);
            while (log.size() > 80) log.remove(log.size() - 1);
            saveLog();
            emit();
        }
    }

    private void emit() {
        List<Runnable> copy;
        synchronized (listeners) { copy = new ArrayList<Runnable>(listeners); }
        for (Runnable r : copy) {
            try { r.run(); } catch (RuntimeException ignored) {}
        }
    }

    private static String safeName(String name) {
        String base = name == null ? "" : name.replace("/", "").replace("\\", "").replace("\u0000", "").trim();
        if (base.length() > 180) base = base.substring(0, 180);
        return base.isEmpty() ? "file.bin" : base;
    }

    private static String sha256(byte[] data) {
        try {
            return Hex.encode(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private void load() {
        contacts.addAll(readContacts(new File(dataDir, "contacts.json")));
        messages.addAll(readMessages(new File(dataDir, "messages.json")));
        files.addAll(readFiles(new File(dataDir, "files.json")));
    }

    private void saveContacts() {
        List<Object> arr = new ArrayList<Object>();
        for (Contact c : contacts) {
            Map<String, Object> o = new LinkedHashMap<String, Object>();
            o.put("fingerprint", c.fingerprint);
            o.put("pubHex", c.pubHex);
            o.put("host", c.host);
            o.put("port", Integer.valueOf(c.port));
            o.put("name", c.name);
            o.put("addedAt", Long.valueOf(c.addedAt));
            arr.add(o);
        }
        writeText(new File(dataDir, "contacts.json"), Json.stringify(arr));
    }

    private void saveMessages() {
        List<Object> arr = new ArrayList<Object>();
        for (ChatLine m : messages) {
            Map<String, Object> o = new LinkedHashMap<String, Object>();
            o.put("id", m.id);
            o.put("fp", m.fp);
            o.put("fromMe", Boolean.valueOf(m.fromMe));
            o.put("text", m.text);
            o.put("at", Long.valueOf(m.at));
            arr.add(o);
        }
        writeText(new File(dataDir, "messages.json"), Json.stringify(arr));
    }

    private void saveFiles() {
        List<Object> arr = new ArrayList<Object>();
        for (VaultFile f : files) {
            Map<String, Object> o = new LinkedHashMap<String, Object>();
            o.put("id", f.id);
            o.put("name", f.name);
            o.put("size", Integer.valueOf(f.size));
            o.put("hash", f.hash);
            o.put("chunks", Integer.valueOf(f.chunks));
            o.put("at", Long.valueOf(f.at));
            o.put("from", f.from);
            arr.add(o);
        }
        writeText(new File(dataDir, "files.json"), Json.stringify(arr));
    }

    private void saveLog() {
        writeText(new File(dataDir, "log.json"), Json.stringify(new ArrayList<Object>(log)));
    }

    @SuppressWarnings("unchecked")
    private static List<Contact> readContacts(File file) {
        List<Contact> out = new ArrayList<Contact>();
        Object parsed = readJson(file);
        if (!(parsed instanceof List)) return out;
        for (Object item : (List<Object>) parsed) {
            if (!(item instanceof Map)) continue;
            Map<String, Object> o = (Map<String, Object>) item;
            out.add(new Contact(Json.str(o, "fingerprint"), Json.str(o, "pubHex"), Json.str(o, "host"),
                    Json.num(o, "port"), Json.str(o, "name"),
                    o.get("addedAt") instanceof Number ? ((Number) o.get("addedAt")).longValue() : 0L));
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static List<ChatLine> readMessages(File file) {
        List<ChatLine> out = new ArrayList<ChatLine>();
        Object parsed = readJson(file);
        if (!(parsed instanceof List)) return out;
        for (Object item : (List<Object>) parsed) {
            if (!(item instanceof Map)) continue;
            Map<String, Object> o = (Map<String, Object>) item;
            out.add(new ChatLine(Json.str(o, "id"), Json.str(o, "fp"), Boolean.TRUE.equals(o.get("fromMe")),
                    Json.str(o, "text"), o.get("at") instanceof Number ? ((Number) o.get("at")).longValue() : 0L));
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static List<VaultFile> readFiles(File file) {
        List<VaultFile> out = new ArrayList<VaultFile>();
        Object parsed = readJson(file);
        if (!(parsed instanceof List)) return out;
        for (Object item : (List<Object>) parsed) {
            if (!(item instanceof Map)) continue;
            Map<String, Object> o = (Map<String, Object>) item;
            String from = o.get("from") == null ? null : String.valueOf(o.get("from"));
            if ("null".equals(from)) from = null;
            out.add(new VaultFile(Json.str(o, "id"), Json.str(o, "name"), Json.num(o, "size"), Json.str(o, "hash"),
                    Json.num(o, "chunks"), o.get("at") instanceof Number ? ((Number) o.get("at")).longValue() : 0L, from));
        }
        return out;
    }

    private static Object readJson(File file) {
        if (!file.isFile()) return null;
        try {
            return Json.parse(new String(readAll(file), "UTF-8"));
        } catch (Exception e) {
            return null;
        }
    }

    private static void writeText(File file, String text) {
        try {
            writeAll(file, text.getBytes("UTF-8"));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] readAll(File file) throws IOException {
        FileInputStream in = new FileInputStream(file);
        try {
            byte[] buf = new byte[(int) file.length()];
            int o = 0;
            while (o < buf.length) {
                int n = in.read(buf, o, buf.length - o);
                if (n < 0) break;
                o += n;
            }
            return buf;
        } finally {
            in.close();
        }
    }

    private static void writeAll(File file, byte[] data) throws IOException {
        File parent = file.getParentFile();
        if (parent != null && !parent.isDirectory()) parent.mkdirs();
        FileOutputStream out = new FileOutputStream(file);
        try {
            out.write(data);
        } finally {
            out.close();
        }
    }

    private static final class Link {
        final Socket socket;
        final byte[] key;
        final Contact remote;
        Link(Socket socket, byte[] key, Contact remote) {
            this.socket = socket;
            this.key = key;
            this.remote = remote;
        }
    }

    private static final class Incoming {
        final String id;
        final String name;
        final int chunks;
        final String fp;
        final byte[][] bufs;
        Incoming(String id, String name, int chunks, String fp) {
            this.id = id;
            this.name = name;
            this.chunks = chunks;
            this.fp = fp;
            this.bufs = new byte[chunks][];
        }
    }
}
