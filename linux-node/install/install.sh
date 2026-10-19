#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"
SHARE="$PREFIX/share/nexxus"
BIN="$PREFIX/bin"
DATA="${NEXXUS_DATA:-$HOME/.nexxus}"

if ! command -v node >/dev/null 2>&1; then
  echo "Нужен Node.js 22+. Установите его и повторите." >&2
  exit 1
fi
major="$(node -p 'process.versions.node.split(".")[0]')"
if [ "$major" -lt 22 ]; then
  echo "Найден Node $(node -v). Нужен 22+." >&2
  exit 1
fi

mkdir -p "$SHARE/lib" "$BIN" "$DATA"
cp "$ROOT/nexxus.mjs" "$ROOT/package.json" "$ROOT/README.md" "$ROOT/dashboard.html" "$SHARE/"
cp "$ROOT/lib/"*.mjs "$SHARE/lib/"
chmod 755 "$SHARE/nexxus.mjs"

(cd "$SHARE" && npm install --omit=dev)

cat > "$BIN/nexxus" <<EOF
#!/usr/bin/env bash
exec node "$SHARE/nexxus.mjs" "\$@"
EOF
chmod 755 "$BIN/nexxus"

echo
echo "Установлено: $BIN/nexxus"
echo "Данные ноды: $DATA"
echo
echo "Запуск:"
echo "  export PATH=\"$BIN:\$PATH\""
echo "  nexxus start --data \"$DATA\""
echo

if command -v systemctl >/dev/null 2>&1 && [ -f "$ROOT/install/nexxus.service" ]; then
  UNIT_DIR="$HOME/.config/systemd/user"
  mkdir -p "$UNIT_DIR"
  sed -e "s|@BIN@|$BIN/nexxus|g" \
      -e "s|@DATA@|$DATA|g" \
      -e "s|@SHARE@|$SHARE|g" \
      "$ROOT/install/nexxus.service" > "$UNIT_DIR/nexxus.service"
  systemctl --user daemon-reload || true
  echo "systemd user-юнит записан: nexxus.service"
  echo "  systemctl --user enable --now nexxus"
  echo
fi

echo "Панель — только на этом компьютере (127.0.0.1:4378)."
echo "Mesh — TCP 4377, откройте его, если второй хост снаружи."
echo "При первом старте запишите фразу BIP39 — она больше не покажется."
