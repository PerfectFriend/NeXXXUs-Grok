import net from "node:net";
import { parseContact, formatContact, generateEph, deriveSessionKey, hexToBytes, signHello, verifyHello } from "./identity.mjs";
import { encodeFrame, decodeFrame } from "./crypto-io.mjs";

const HELLO_TIMEOUT_MS = 12_000;

function readLengthPrefixed(socket, onFrame) {
  let buf = Buffer.alloc(0);
  socket.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 4) {
      const n = buf.readUInt32BE(0);
      if (n > 8 * 1024 * 1024) {
        socket.destroy(new Error("frame too large"));
        return;
      }
      if (buf.length < 4 + n) break;
      const payload = buf.subarray(4, 4 + n);
      buf = buf.subarray(4 + n);
      onFrame(payload);
    }
  });
}

function writeFrame(socket, bytes) {
  const header = Buffer.alloc(4);
  header.writeUInt32BE(bytes.length, 0);
  socket.write(Buffer.concat([header, Buffer.from(bytes)]));
}

function writeJson(socket, obj) {
  writeFrame(socket, Buffer.from(JSON.stringify(obj)));
}

export function createMesh({ identity, advertise, listenHost, listenPort, onEvent, onPacket }) {
  /** @type {Map<string, any>} */
  const links = new Map();
  let server = null;

  function log(text) {
    onEvent?.({ kind: "log", text });
  }

  function helloPayload(ephPubHex) {
    return signHello(identity, {
      eph: ephPubHex,
      name: advertise.name,
      host: advertise.host,
      port: listenPort,
    });
  }

  function drop(fp, reason) {
    const link = links.get(fp);
    if (!link) return;
    try {
      link.socket.destroy();
    } catch {
      /* ignore */
    }
    links.delete(fp);
    onEvent?.({ kind: "peer", fp, online: false, reason });
  }

  function attach(socket, { expected, inbound }) {
    const eph = generateEph();
    let established = false;
    let key = null;
    let fp = expected?.fingerprint ?? null;
    let remote = expected ? { ...expected } : null;
    const pending = [];

    const timer = setTimeout(() => {
      if (!established) socket.destroy();
    }, HELLO_TIMEOUT_MS);

    const finishHello = (msg) => {
      try {
        verifyHello(msg);
      } catch (err) {
        log(`Hello отвергнут: ${err.message}`);
        socket.destroy();
        return;
      }
      if (msg.fp === identity.fingerprint) {
        log("Входящее соединение с собственным ключом — отброшено.");
        socket.destroy();
        return;
      }
      if (expected && (expected.fingerprint !== msg.fp || expected.pubHex !== msg.pub.toLowerCase())) {
        log(`Ключ не совпал с контактом ${expected.fingerprint}.`);
        socket.destroy();
        return;
      }
      fp = msg.fp;
      remote = {
        fingerprint: msg.fp,
        pubHex: msg.pub.toLowerCase(),
        host: msg.host || expected?.host,
        port: msg.port || expected?.port,
        name: msg.name || msg.fp,
      };
      try {
        key = deriveSessionKey({
          myStaticPriv: identity.xPriv,
          myStaticPub: identity.xPub,
          myEphPriv: eph.secretKey,
          theirStaticPub: hexToBytes(msg.pub),
          theirEphPub: hexToBytes(msg.eph),
          initiator: !inbound,
        });
      } catch (err) {
        log(`X25519 отверг ключ: ${err.message}`);
        socket.destroy();
        return;
      }
      const prev = links.get(fp);
      if (prev && prev.socket !== socket) {
        try {
          prev.socket.destroy();
        } catch {
          /* ignore */
        }
      }
      links.set(fp, { socket, key, remote, inbound: !!inbound });
      established = true;
      clearTimeout(timer);
      onEvent?.({
        kind: "peer",
        fp,
        online: true,
        contact: formatContact({
          fingerprint: remote.fingerprint,
          pubHex: remote.pubHex,
          host: remote.host,
          port: remote.port,
        }),
        remote,
      });
      log(`Канал с ${remote.name} (${fp}) установлен. Сессия X25519 4DH.`);
      for (const obj of pending) send(fp, obj);
      pending.length = 0;
    };

    readLengthPrefixed(socket, (payload) => {
      try {
        if (!established) {
          finishHello(JSON.parse(payload.toString("utf8")));
          return;
        }
        const obj = decodeFrame(key, new Uint8Array(payload));
        onPacket?.(fp, obj);
      } catch (err) {
        log(`Ошибка кадра: ${err.message}`);
        socket.destroy();
      }
    });

    socket.on("error", () => {});
    socket.on("close", () => {
      clearTimeout(timer);
      if (fp && links.get(fp)?.socket === socket) {
        links.delete(fp);
        onEvent?.({ kind: "peer", fp, online: false });
        log(`Канал с ${fp} закрыт.`);
      }
    });

    writeJson(socket, helloPayload(eph.pubHex));

    return {
      send(obj) {
        if (!established) {
          pending.push(obj);
          return;
        }
        writeFrame(socket, Buffer.from(encodeFrame(key, obj)));
      },
    };
  }

  function listen() {
    server = net.createServer((socket) => {
      socket.setKeepAlive(true, 15_000);
      attach(socket, { inbound: true });
    });
    return new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(listenPort, listenHost, () => {
        log(`Mesh слушает ${listenHost}:${listenPort}`);
        resolve();
      });
    });
  }

  function dial(contact) {
    const spec = typeof contact === "string" ? parseContact(contact) : contact;
    if (spec.fingerprint === identity.fingerprint) throw new Error("Нельзя добавить свой контакт.");
    const existing = links.get(spec.fingerprint);
    if (existing && !existing.socket.destroyed) return spec;
    const socket = net.connect({ host: spec.host, port: spec.port });
    socket.setKeepAlive(true, 15_000);
    attach(socket, { expected: spec, inbound: false });
    socket.on("error", (err) => {
      log(`Не удалось дозвониться до ${spec.host}:${spec.port} — ${err.message}`);
      onEvent?.({ kind: "peer", fp: spec.fingerprint, online: false, reason: err.message });
    });
    return spec;
  }

  function send(fp, obj) {
    const link = links.get(fp);
    if (!link || link.socket.destroyed) throw new Error("Нет живого канала. Добавьте контакт и дождитесь связи.");
    writeFrame(link.socket, Buffer.from(encodeFrame(link.key, obj)));
  }

  function isOnline(fp) {
    const link = links.get(fp);
    return !!(link && !link.socket.destroyed);
  }

  function stop() {
    for (const fp of [...links.keys()]) drop(fp, "stop");
    return new Promise((resolve) => {
      if (!server) return resolve();
      server.close(() => resolve());
    });
  }

  return { listen, dial, send, isOnline, stop, links };
}