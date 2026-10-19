#!/usr/bin/env bash
set -euo pipefail

PREFIX="${PREFIX:-$HOME/.local}"
SHARE="$PREFIX/share/nexxus"
BIN="$PREFIX/bin/nexxus"
DATA="${NEXXUS_DATA:-$HOME/.nexxus}"

if command -v systemctl >/dev/null 2>&1; then
  systemctl --user disable --now nexxus 2>/dev/null || true
  rm -f "$HOME/.config/systemd/user/nexxus.service"
  systemctl --user daemon-reload 2>/dev/null || true
fi

rm -f "$BIN"
rm -rf "$SHARE"

echo "Бинарник и файлы установки удалены."
echo "Данные ноды ($DATA) не трогал. Чтобы стереть ключ и сейф:"
echo "  rm -rf \"$DATA\""
