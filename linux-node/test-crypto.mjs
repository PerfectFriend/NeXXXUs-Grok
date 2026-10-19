import {
  x25519,
  hexToBytes,
  bytesToHex,
  generateEph,
  deriveSessionKey,
  deriveIdentity,
  fingerprintFromPub,
  parseContact,
  formatContact,
  signHello,
  verifyHello,
} from "./lib/identity.mjs";

function eq(name, a, b) {
  if (a !== b) throw new Error(`${name}: ${a} !== ${b}`);
}

// RFC 7748 §6.1
const alicePriv = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
const bobPriv = hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
eq("alice pub", bytesToHex(x25519.getPublicKey(alicePriv)), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
eq("bob pub", bytesToHex(x25519.getPublicKey(bobPriv)), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
const shared = x25519.getSharedSecret(alicePriv, x25519.getPublicKey(bobPriv));
eq("shared", bytesToHex(shared), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
eq("commutative", bytesToHex(shared), bytesToHex(x25519.getSharedSecret(bobPriv, x25519.getPublicKey(alicePriv))));

eq(
  "vec1",
  bytesToHex(
    x25519.getSharedSecret(
      hexToBytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
      hexToBytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    ),
  ),
  "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
);

const nine = hexToBytes("09" + "00".repeat(31));
eq(
  "iter1",
  bytesToHex(x25519.getSharedSecret(nine, nine)),
  "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
);

let rejected = false;
try {
  x25519.getSharedSecret(alicePriv, new Uint8Array(32));
} catch {
  rejected = true;
}
if (!rejected) throw new Error("low-order public key was accepted");

const phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const idA = deriveIdentity(phrase);
const idB = deriveIdentity("letter advice cage absurd amount doctor acoustic avoid letter advice cage above");
eq("fp bound", idA.fingerprint, fingerprintFromPub(idA.xPub));
eq("fp not seed", idA.fingerprint.startsWith("nxx1"), true);

let mixed = false;
try {
  parseContact(`nexxus:1:${idB.fingerprint}:${idA.pubHex}@127.0.0.1:4377`);
} catch {
  mixed = true;
}
if (!mixed) throw new Error("mixed fingerprint/pub was accepted");

const uri = formatContact({ fingerprint: idA.fingerprint, pubHex: idA.pubHex, host: "10.0.0.8", port: 4377 });
eq("roundtrip fp", parseContact(uri).fingerprint, idA.fingerprint);

const hello = signHello(idA, { eph: generateEph().pubHex, name: "alpha", host: "10.0.0.8", port: 4377 });
verifyHello(hello);
const tampered = { ...hello, host: "evil.example" };
let bad = false;
try {
  verifyHello(tampered);
} catch {
  bad = true;
}
if (!bad) throw new Error("tampered hello verified");

const eA = generateEph();
const eB = generateEph();
const kInit = deriveSessionKey({
  myStaticPriv: idA.xPriv,
  myStaticPub: idA.xPub,
  myEphPriv: eA.secretKey,
  theirStaticPub: idB.xPub,
  theirEphPub: eB.publicKey,
  initiator: true,
});
const kResp = deriveSessionKey({
  myStaticPriv: idB.xPriv,
  myStaticPub: idB.xPub,
  myEphPriv: eB.secretKey,
  theirStaticPub: idA.xPub,
  theirEphPub: eA.publicKey,
  initiator: false,
});
eq("session symmetric", bytesToHex(kInit), bytesToHex(kResp));

console.log("CRYPTO OK");