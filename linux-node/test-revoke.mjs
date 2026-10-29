import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { bytesToHex, randomBytes } from "@noble/hashes/utils.js";
import { createMnemonic, deriveDevice, deriveIdentity } from "./lib/identity.mjs";
import { openVault } from "./lib/vault.mjs";

function identity(mnemonic) {
  const id = deriveIdentity(mnemonic);
  id.device = deriveDevice(id.seed, bytesToHex(randomBytes(16)));
  return id;
}

const mnemonic = createMnemonic();
const owner = identity(mnemonic);
const other = identity(mnemonic);
const ownerDir = await mkdtemp(path.join(os.tmpdir(), "nxx-revoke-a-"));
const otherDir = await mkdtemp(path.join(os.tmpdir(), "nxx-revoke-b-"));
const vaultA = await openVault({ dataDir: ownerDir, identity: owner });
const vaultB = await openVault({ dataDir: otherDir, identity: other });

try {
  await vaultA.addFile({
    id: "keep",
    name: "keep.txt",
    bytes: new TextEncoder().encode("still-here"),
  });
  if (!(await vaultB.importPacked(vaultA.packed()))) throw new Error("второе устройство не приняло журнал");
  if (!vaultB.list().some((file) => file.name === "keep.txt")) throw new Error("файл не доехал до второго устройства");
  if (!(await vaultA.importPacked(vaultB.packed()))) throw new Error("владелец не увидел новое устройство");
  await vaultB.addFile({ id: "evil", name: "evil.txt", bytes: new TextEncoder().encode("nope") });
  let self = false;
  try {
    await vaultA.revokeDevice(bytesToHex(owner.device.edPub));
  } catch (err) {
    self = String(err.message).includes("с которого");
  }
  if (!self) throw new Error("устройство смогло отозвать само себя");
  if (!(await vaultA.revokeDevice(bytesToHex(other.device.edPub)))) throw new Error("отзыв не записался");
  if (!(await vaultA.importPacked(vaultB.packed()))) throw new Error("чужой журнал не слился");
  if (vaultA.list().some((file) => file.name === "evil.txt")) throw new Error("запись отозванного устройства попала в карту");
  if (!(await vaultB.importPacked(vaultA.packed()))) throw new Error("отзыв не дошёл до отозванного");
  let refused = false;
  try {
    await vaultB.addFile({ id: "evil2", name: "evil2.txt", bytes: new TextEncoder().encode("nope") });
  } catch (err) {
    refused = String(err.message).includes("отозвано");
  }
  if (!refused) throw new Error("отозванное устройство записало файл");
  const plain = await vaultA.readPlain("keep");
  if (new TextDecoder().decode(plain.bytes) !== "still-here") throw new Error("сейф повреждён отзывом");
  console.log("REVOKE OK");
} finally {
  await rm(ownerDir, { recursive: true, force: true });
  await rm(otherDir, { recursive: true, force: true });
}
