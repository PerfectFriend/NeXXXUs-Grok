import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createNode } from "./lib/node.mjs";
import { renderTorrc } from "./lib/tor.mjs";

const onion = `${"d".repeat(56)}.onion`;
const rc = renderTorrc({
  dataDir: "/tmp/nexxus-tor-data",
  socksPort: 9050,
  hsDir: "/tmp/nexxus-tor-hs",
  virtPort: 4377,
  targetPort: 4377,
});
if (!rc.includes('HiddenServiceDir "/tmp/nexxus-tor-hs"')) throw new Error("torrc без каталога службы");
if (!rc.includes("HiddenServicePort 4377 127.0.0.1:4377")) throw new Error("torrc без проброса порта");
if (!rc.includes("SocksPort 127.0.0.1:9050")) throw new Error("torrc без SOCKS");

const missingDir = await mkdtemp(path.join(os.tmpdir(), "nxx-tor-miss-"));
let missing = "";
try {
  await createNode({
    data: missingDir,
    port: 18811,
    http: 18812,
    host: "0.0.0.0",
    name: "no-tor",
    profile: "onion",
    torBin: "/no/such/nexxus-tor",
  });
} catch (err) {
  missing = String(err.message);
} finally {
  await rm(missingDir, { recursive: true, force: true });
}
if (!missing.includes("Не удалось запустить Tor")) throw new Error(`вместо отказа: ${missing}`);

const dir = await mkdtemp(path.join(os.tmpdir(), "nxx-tor-stub-"));
const stub = path.join(dir, "tor-stub.mjs");
await writeFile(
  stub,
  `#!/usr/bin/env node
import { mkdir, readFile, writeFile } from "node:fs/promises";
const rcPath = process.argv[process.argv.indexOf("-f") + 1];
const text = await readFile(rcPath, "utf8");
const hs = text.match(/^HiddenServiceDir "?([^"\\n]+)"?$/m)?.[1];
if (!hs) process.exit(2);
await mkdir(hs, { recursive: true, mode: 0o700 });
await writeFile(hs + "/hostname", ${JSON.stringify(`${onion}\n`)});
setInterval(() => {}, 1000);
`,
);
await chmod(stub, 0o755);
const node = await createNode({
  data: path.join(dir, "node"),
  port: 18821,
  http: 18822,
  host: "0.0.0.0",
  name: "stub-tor",
  profile: "onion",
  torBin: stub,
});
try {
  if (!node.contact.includes(`@${onion}:18821`)) throw new Error(`контакт не из hostname: ${node.contact}`);
  if (node.snapshot().listen.host !== "127.0.0.1") throw new Error("служба смотрит наружу");
  console.log("TOR OK");
} finally {
  await node.stop();
  await rm(dir, { recursive: true, force: true });
}
