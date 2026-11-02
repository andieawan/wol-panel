#!/usr/bin/env bash
# Perbarui WOL Panel dari repo:  cd ~/wol-panel && sudo bash deploy/update.sh
# Dipakai juga oleh tombol "Update aplikasi" di menu Server (VM tempat panel berjalan).
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Jalankan dengan sudo." >&2; exit 1; }
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
echo "==> git pull"
git pull --ff-only
echo
echo "==> Pasang ke /opt/wol-panel"
# restart ditunda agar panel sempat menyelesaikan dan mencatat proses update ini
WOL_DEFER_RESTART=1 bash install.sh
echo "Selesai. Versi: $(git rev-parse --short HEAD)"
