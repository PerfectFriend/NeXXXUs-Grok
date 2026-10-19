#!/usr/bin/env node
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createNode, parseArgs } from "./lib/node.mjs";
import { serveHttp } from "./lib/http.mjs";

export { createNode, parseArgs };

async function main() {
  const args = parseArgs(process.argv);
  if (args.cmd === "help" || args.cmd === "--help" || args.cmd === "-h") {
    console.log(`NeXXUs Linux beta

  node nexxus.mjs start [опции]
    --data DIR         каталог ноды (по умолчанию ~/.nexxus)
    --port N           mesh TCP, по умолчанию 4377
    --http N           панель, по умолчанию 4378
    --host ADDR        bind mesh, по умолчанию 0.0.0.0
    --http-host ADDR   bind панели, по умолчанию 127.0.0.1
    --advertise HOST   адрес в контакте (иначе LAN IP)
    --name NAME        имя ноды
    --mnemonic "…"     восстановить ключ BIP39

Два хоста: поднимите ноду, обменяйтесь строкой контакта, вставьте её в панель.
Один из хостов должен быть доступен по адресу из контакта (одна сеть, VPS или проброс порта).
`);
    return;
  }

  const node = await createNode(args);
  const httpServer = await serveHttp(node, { host: args.httpHost || "127.0.0.1", port: args.http });
  void httpServer;

  console.log("");
  console.log("NeXXUs  ·  Linux beta 0.1.2");
  console.log("ключ     ", node.identity.fingerprint);
  if (node.fresh && node.mnemonic) {
    console.log("");
    console.log("BIP39 (запишите, больше не повторится в логе):");
    console.log(node.mnemonic);
    console.log("");
  }
  console.log("контакт  ", node.contact);
  console.log("панель   ", `http://${args.httpHost || "127.0.0.1"}:${args.http}/`);
  console.log("");
  console.log("Вставьте контакт второго хоста в панель → Связь.");
  console.log("Ctrl+C — остановить.");

  const stop = async () => {
    await node.stop();
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}

const self = fileURLToPath(import.meta.url);
if (process.argv[1] && path.resolve(process.argv[1]) === self) {
  main().catch((err) => {
    console.error(err.message || err);
    process.exit(1);
  });
}
