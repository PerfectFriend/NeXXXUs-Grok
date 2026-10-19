import { mkdir, writeFile } from "node:fs/promises";
import { createNode } from "../../linux-node/lib/node.mjs";

const port = Number(process.argv[2]);
const data = process.argv[3];
const contactFile = process.argv[4];
await mkdir(data, { recursive: true });
const n = await createNode({
  data,
  port,
  http: port + 1,
  host: "127.0.0.1",
  advertise: "127.0.0.1",
  name: "linuxbox",
});
await writeFile(contactFile, n.contact);
const seen = new Set();
setInterval(() => {
  for (const m of n.snapshot().messages) {
    if (m.fromMe || seen.has(m.id)) continue;
    seen.add(m.id);
    n.sendChat(m.fp, "linux-pong:" + m.text);
    n.storePlainFile({ name: "from-linux.txt", bytes: Buffer.from("linux-file-ok") })
      .then((rec) => n.sendFile(m.fp, rec.id))
      .catch((err) => console.error(err));
  }
}, 200);
