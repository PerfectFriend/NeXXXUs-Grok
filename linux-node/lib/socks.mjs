import net from "node:net";

export function isOnion(host) {
  return /^[a-z2-7]{56}\.onion$/i.test(String(host ?? ""));
}

export function parseSocks(value) {
  const raw = String(value ?? "").trim();
  if (!raw) return null;
  const match = raw.match(/^([^:\s]+):(\d{1,5})$/);
  if (!match) throw new Error("Tor SOCKS задаётся как host:port.");
  const port = Number(match[2]);
  if (port < 1 || port > 65535) throw new Error("Некорректный порт SOCKS.");
  return { host: match[1], port };
}

export function connectViaSocks({ socksHost, socksPort, host, port }) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: socksHost, port: socksPort });
    let stage = 0;
    let buf = Buffer.alloc(0);
    const fail = (err) => {
      socket.destroy();
      reject(err instanceof Error ? err : new Error(String(err)));
    };
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (stage === 0) {
        if (buf.length < 2) return;
        if (buf[0] !== 5 || buf[1] !== 0) {
          fail(new Error("SOCKS не принял соединение без пароля."));
          return;
        }
        buf = buf.subarray(2);
        const name = Buffer.from(String(host));
        if (name.length < 1 || name.length > 255) {
          fail(new Error("Адрес для SOCKS пустой или слишком длинный."));
          return;
        }
        const req = Buffer.alloc(7 + name.length);
        req[0] = 5;
        req[1] = 1;
        req[2] = 0;
        req[3] = 3;
        req[4] = name.length;
        name.copy(req, 5);
        req.writeUInt16BE(port, 5 + name.length);
        socket.write(req);
        stage = 1;
      }
      if (stage !== 1 || buf.length < 4) return;
      const atyp = buf[3];
      let need = 4;
      if (atyp === 1) need += 6;
      else if (atyp === 4) need += 18;
      else if (atyp === 3) {
        if (buf.length < 5) return;
        need += 1 + buf[4] + 2;
      } else {
        fail(new Error("SOCKS вернул неизвестный тип адреса."));
        return;
      }
      if (buf.length < need) return;
      if (buf[1] !== 0) {
        fail(new Error(`SOCKS отказал в соединении, код ${buf[1]}.`));
        return;
      }
      const rest = buf.subarray(need);
      socket.off("data", onData);
      socket.off("error", fail);
      if (rest.length) socket.unshift(rest);
      resolve(socket);
    };
    socket.once("error", fail);
    socket.on("data", onData);
    socket.once("connect", () => {
      socket.write(Buffer.from([5, 1, 0]));
    });
  });
}
