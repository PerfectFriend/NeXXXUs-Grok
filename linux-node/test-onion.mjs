import net from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createNode } from "./lib/node.mjs";

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function until(fn, label, tries = 50) {
  for (let i = 0; i < tries; i++) {
    const value = fn();
    if (value) return value;
    await wait(100);
  }
  throw new Error(`timeout: ${label}`);
}

function startSocks() {
  const hits = [];
  const server = net.createServer((socket) => {
    let stage = 0;
    let buf = Buffer.alloc(0);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (stage === 0) {
        if (buf.length < 2) return;
        const methods = buf[1];
        if (buf.length < 2 + methods) return;
        buf = buf.subarray(2 + methods);
        socket.write(Buffer.from([5, 0]));
        stage = 1;
      }
      if (stage !== 1 || buf.length < 5) return;
      if (buf[3] !== 3) {
        socket.destroy();
        return;
      }
      const len = buf[4];
      if (buf.length < 7 + len) return;
      const host = buf.subarray(5, 5 + len).toString();
      const port = buf.readUInt16BE(5 + len);
      const rest = buf.subarray(7 + len);
      hits.push(host);
      socket.off("data", onData);
      socket.pause();
      const upstream = net.connect({ host: "127.0.0.1", port }, () => {
        const reply = Buffer.alloc(10);
        reply[0] = 5;
        reply[3] = 1;
        socket.write(reply);
        if (rest.length) upstream.write(rest);
        socket.pipe(upstream);
        upstream.pipe(socket);
        socket.resume();
      });
      upstream.on("error", () => socket.destroy());
      stage = 2;
    };
    socket.on("data", onData);
    socket.on("error", () => {});
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        port: server.address().port,
        hits,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

const onionA = `${"a".repeat(56)}.onion`;
const onionB = `${"b".repeat(56)}.onion`;
const socks = await startSocks();
const dirA = await mkdtemp(path.join(os.tmpdir(), "nxx-onion-a-"));
const dirB = await mkdtemp(path.join(os.tmpdir(), "nxx-onion-b-"));
const a = await createNode({
  data: dirA,
  port: 18711,
  http: 18712,
  host: "0.0.0.0",
  advertise: onionA,
  name: "onion-a",
  profile: "onion",
  torSocks: `127.0.0.1:${socks.port}`,
});
const b = await createNode({
  data: dirB,
  port: 18721,
  http: 18722,
  host: "0.0.0.0",
  advertise: onionB,
  name: "onion-b",
  profile: "onion",
  torSocks: `127.0.0.1:${socks.port}`,
});

try {
  if (a.snapshot().listen.host !== "127.0.0.1") throw new Error("луковый профиль открыл прямой адрес");
  let rejected = false;
  try {
    await b.addContact(a.contact.replace(`@${onionA}:`, "@127.0.0.1:"));
  } catch (err) {
    rejected = String(err.message).includes(".onion");
  }
  if (!rejected) throw new Error("прямой IP принят в луковом профиле");

  await b.addContact(a.contact);
  await until(() => b.snapshot().contacts.some((c) => c.online) && a.snapshot().contacts.some((c) => c.online), "link");
  if (!socks.hits.includes(onionA)) throw new Error("звонок прошёл мимо SOCKS");
  b.sendChat(a.identity.fingerprint, "через socks");
  await until(() => a.snapshot().messages.some((m) => m.text === "через socks" && !m.fromMe), "chat");
  console.log("ONION OK");
} finally {
  await a.stop();
  await b.stop();
  await socks.close();
  await rm(dirA, { recursive: true, force: true });
  await rm(dirB, { recursive: true, force: true });
}
