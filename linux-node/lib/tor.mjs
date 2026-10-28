import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { isOnion } from "./socks.mjs";

function quote(value) {
  return `"${String(value).replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

export function renderTorrc({ dataDir, socksPort, hsDir, virtPort, targetPort }) {
  return [
    `DataDirectory ${quote(dataDir)}`,
    `SocksPort 127.0.0.1:${socksPort}`,
    `HiddenServiceDir ${quote(hsDir)}`,
    `HiddenServicePort ${virtPort} 127.0.0.1:${targetPort}`,
    "Log notice stdout",
    "",
  ].join("\n");
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
  });
}

export async function startTor({ bin = "tor", root, listenPort, timeoutMs = 90_000 }) {
  const dataDir = path.join(root, "data");
  const hsDir = path.join(root, "hs");
  await mkdir(dataDir, { recursive: true });
  await mkdir(hsDir, { recursive: true, mode: 0o700 });
  const socksPort = await freePort();
  const torrcPath = path.join(root, "torrc");
  await writeFile(torrcPath, renderTorrc({ dataDir, socksPort, hsDir, virtPort: listenPort, targetPort: listenPort }));
  const child = spawn(bin, ["-f", torrcPath], { stdio: ["ignore", "pipe", "pipe"] });
  let log = "";
  child.stdout?.on("data", (chunk) => {
    log = (log + chunk).slice(-2000);
  });
  child.stderr?.on("data", (chunk) => {
    log = (log + chunk).slice(-2000);
  });
  const spawned = new Promise((resolve, reject) => {
    child.once("spawn", resolve);
    child.once("error", (err) => {
      reject(new Error(`Не удалось запустить Tor (${bin}): ${err.message}`));
    });
  });
  try {
    await spawned;
  } catch (err) {
    throw err;
  }
  const hostnamePath = path.join(hsDir, "hostname");
  const started = Date.now();
  let onion = "";
  while (Date.now() - started < timeoutMs) {
    if (child.exitCode !== null) {
      throw new Error(`Tor завершился сразу, код ${child.exitCode}. ${log.trim()}`);
    }
    try {
      const text = (await readFile(hostnamePath, "utf8")).trim().split(/\s+/)[0] ?? "";
      if (isOnion(text)) {
        onion = text.toLowerCase();
        break;
      }
    } catch {
      /* файла ещё нет */
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  if (!onion) {
    child.kill("SIGTERM");
    throw new Error(`Tor не записал v3-адрес в hostname. Адрес не подставляется. ${log.trim()}`);
  }
  return {
    onion,
    socksPort,
    stop() {
      if (child.exitCode === null) child.kill("SIGTERM");
    },
  };
}
