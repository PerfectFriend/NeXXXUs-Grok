import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createNode } from "./lib/node.mjs";

const dir = await mkdtemp(path.join(os.tmpdir(), "nxx-drive-"));
const node = await createNode({
  data: dir,
  port: 18611,
  http: 18612,
  host: "127.0.0.1",
  advertise: "127.0.0.1",
  name: "drive",
});

try {
  const drive = node.snapshot().drive;
  const file = path.join(drive, "note.txt");
  await writeFile(file, "hello-drive");
  await node.syncDrive();
  const rec = node.snapshot().files.find((item) => item.name === "note.txt");
  if (!rec) throw new Error("файл из каталога не попал в сейф");
  const loaded = await node.loadPlainFile(rec.id);
  if (new TextDecoder().decode(loaded.bytes) !== "hello-drive") throw new Error("прочиталось не то");

  await writeFile(file, "hello-edited");
  await node.syncDrive();
  const edited = node.snapshot().files.filter((item) => item.name === "note.txt");
  if (edited.length !== 1) throw new Error(`после правки файлов ${edited.length}`);
  const again = await node.loadPlainFile(edited[0].id);
  if (new TextDecoder().decode(again.bytes) !== "hello-edited") throw new Error("правка не записалась");

  await rm(file);
  await node.syncDrive();
  if (node.snapshot().files.some((item) => item.name === "note.txt")) throw new Error("удаление из каталога не сняло файл");

  await node.storePlainFile({ name: "from-net.txt", bytes: new TextEncoder().encode("out") });
  await node.syncDrive();
  const back = await readFile(path.join(drive, "from-net.txt"), "utf8");
  if (back !== "out") throw new Error(`в каталоге ${back}`);
  console.log("DRIVE OK");
} finally {
  await node.stop();
  await rm(dir, { recursive: true, force: true });
}
