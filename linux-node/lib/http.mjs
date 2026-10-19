import http from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const dashboardPath = path.join(here, "..", "dashboard.html");

function safeFilename(raw) {
  let name = String(raw ?? "file.bin");
  try {
    name = decodeURIComponent(name);
  } catch {
    /* keep raw */
  }
  name = name.replace(/[/\\]/g, "").replace(/\0/g, "").trim().slice(0, 180);
  return name || "file.bin";
}

function send(res, status, body, headers = {}) {
  const data = typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  const extra = typeof body === "object" && !Buffer.isBuffer(body) && typeof body !== "string"
    ? { "content-type": "application/json; charset=utf-8" }
    : {};
  res.writeHead(status, { "access-control-allow-origin": "*", ...extra, ...headers });
  res.end(data);
}

function readBody(req, limit = 40 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let n = 0;
    req.on("data", (c) => {
      n += c.length;
      if (n > limit) {
        reject(new Error("too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export async function serveHttp(node, { host, port }) {
  const html = await readFile(dashboardPath, "utf8");
  const server = http.createServer(async (req, res) => {
    try {
      if (req.method === "OPTIONS") {
        res.writeHead(204, {
          "access-control-allow-origin": "*",
          "access-control-allow-headers": "content-type, x-filename, x-to",
          "access-control-allow-methods": "GET,POST,DELETE,OPTIONS",
        });
        res.end();
        return;
      }
      const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
      const p = url.pathname;

      if (req.method === "GET" && (p === "/" || p === "/index.html")) {
        send(res, 200, html, { "content-type": "text/html; charset=utf-8" });
        return;
      }
      if (req.method === "GET" && p === "/api/state") {
        send(res, 200, node.snapshot());
        return;
      }
      if (req.method === "GET" && p === "/api/contact") {
        send(res, 200, node.contact, { "content-type": "text/plain; charset=utf-8" });
        return;
      }
      if (req.method === "POST" && p === "/api/contacts") {
        const body = JSON.parse((await readBody(req, 16_000)).toString("utf8") || "{}");
        const row = await node.addContact(body.uri);
        send(res, 200, row);
        return;
      }
      if (req.method === "POST" && p === "/api/chat") {
        const body = JSON.parse((await readBody(req, 64_000)).toString("utf8") || "{}");
        const msg = node.sendChat(body.fp, body.text);
        send(res, 200, msg);
        return;
      }
      if (req.method === "POST" && p === "/api/files") {
        const filename = safeFilename(req.headers["x-filename"]);
        const to = String(req.headers["x-to"] ?? "");
        const buf = new Uint8Array(await readBody(req));
        const rec = await node.storePlainFile({ name: filename, bytes: buf });
        if (to) await node.sendFile(to, rec.id);
        send(res, 200, rec);
        return;
      }
      if (req.method === "POST" && p.startsWith("/api/files/") && p.endsWith("/send")) {
        const id = p.split("/")[3];
        const body = JSON.parse((await readBody(req, 4000)).toString("utf8") || "{}");
        await node.sendFile(body.fp, id);
        send(res, 200, { ok: true });
        return;
      }
      if (req.method === "GET" && p.startsWith("/api/files/") && p.split("/").length === 4) {
        const id = p.split("/")[3];
        const { rec, bytes } = await node.loadPlainFile(id);
        send(res, 200, Buffer.from(bytes), {
          "content-type": "application/octet-stream",
          "content-disposition": `attachment; filename="${encodeURIComponent(rec.name)}"`,
        });
        return;
      }
      if (req.method === "DELETE" && p.startsWith("/api/files/")) {
        await node.removeFile(p.split("/")[3]);
        send(res, 200, { ok: true });
        return;
      }
      send(res, 404, { error: "not found" });
    } catch (err) {
      send(res, 400, { error: err.message ?? String(err) });
    }
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, resolve);
  });
  return server;
}
