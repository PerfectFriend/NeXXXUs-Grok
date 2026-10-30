import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createNode } from "./lib/node.mjs";

const bin = process.env.NEXXUS_TOR_BIN || "/tmp/tor-bundle/tor/tor";
if (!existsSync(bin)) {
  console.log("TOR LIVE SKIP");
  process.exit(0);
}

const dirA = await mkdtemp(path.join(os.tmpdir(), "nxx-tor-live-a-"));
const dirB = await mkdtemp(path.join(os.tmpdir(), "nxx-tor-live-b-"));
const common = {
  host: "127.0.0.1",
  profile: "onion",
  torBin: bin,
  torTimeoutMs: 180_000,
};
const a = await createNode({ ...common, data: dirA, port: 19011, http: 19012, name: "live-a" });
const b = await createNode({ ...common, data: dirB, port: 19021, http: 19022, name: "live-b" });

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

try {
  const hostA = a.contact.split("@")[1].split(":")[0];
  const hostB = b.contact.split("@")[1].split(":")[0];
  for (const host of [hostA, hostB]) {
    if (!/^[a-z2-7]{56}\.onion$/.test(host)) throw new Error(`не onion: ${host}`);
    if (/^(.)\1{55}\.onion$/.test(host)) throw new Error("адрес похож на заглушку");
  }
  await b.addContact(a.contact);
  const deadline = Date.now() + 180_000;
  while (Date.now() < deadline) {
    const linked = a.snapshot().contacts.some((c) => c.online) && b.snapshot().contacts.some((c) => c.online);
    if (linked) break;
    await wait(500);
  }
  if (!a.snapshot().contacts.some((c) => c.online)) {
    console.error(a.snapshot().log.map((line) => line.text).join("\n"));
    console.error(b.snapshot().log.map((line) => line.text).join("\n"));
    throw new Error("луковый канал не поднялся");
  }
  b.sendChat(a.identity.fingerprint, "через живой tor");
  const chatDeadline = Date.now() + 20_000;
  while (Date.now() < chatDeadline) {
    if (a.snapshot().messages.some((m) => m.text === "через живой tor")) break;
    await wait(200);
  }
  if (!a.snapshot().messages.some((m) => m.text === "через живой tor")) throw new Error("сообщение по луку не дошло");
  console.log("TOR LIVE OK", hostA, hostB);
} finally {
  await a.stop();
  await b.stop();
  await rm(dirA, { recursive: true, force: true });
  await rm(dirB, { recursive: true, force: true });
}
