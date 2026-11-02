#!/usr/bin/env bash
# Pasang / perbarui WOL Panel sebagai layanan systemd (Debian/Ubuntu, termasuk container LXC Proxmox).
# Zona waktu bawaan Asia/Jakarta; ganti dengan: WOL_TZ=Asia/Makassar bash install.sh
set -e
DIR=/opt/wol-panel
WOL_TZ=${WOL_TZ:-Asia/Jakarta}
[ "$(id -u)" = 0 ] || { echo "Jalankan sebagai root: sudo bash install.sh"; exit 1; }

apt-get update -qq && apt-get install -y -qq python3 iputils-ping iputils-arping tzdata >/dev/null

# Zona waktu agar jam di Riwayat sesuai (container baru biasanya masih UTC)
if [ -f "/usr/share/zoneinfo/$WOL_TZ" ] && [ "$(readlink -f /etc/localtime)" != "/usr/share/zoneinfo/$WOL_TZ" ]; then
  ln -sf "/usr/share/zoneinfo/$WOL_TZ" /etc/localtime
  echo "$WOL_TZ" > /etc/timezone
  echo "Zona waktu diatur ke $WOL_TZ"
fi

id wolpanel >/dev/null 2>&1 || useradd --system --home "$DIR" --shell /usr/sbin/nologin wolpanel
mkdir -p "$DIR"
install -m 755 "$(dirname "$0")/wol.py" "$DIR/wol.py"
install -m 644 "$(dirname "$0")/windows-agent.ps1" "$DIR/windows-agent.ps1"

if [ ! -f "$DIR/config.json" ]; then
  echo "== Buat akun admin WOL Panel =="
  (cd "$DIR" && python3 wol.py init)
fi
chown -R wolpanel:wolpanel "$DIR"; chmod 600 "$DIR/config.json"

cat > /etc/systemd/system/wol-panel.service <<EOF
[Unit]
Description=WOL Panel (Wake-on-LAN)
After=network-online.target
Wants=network-online.target

[Service]
User=wolpanel
WorkingDirectory=$DIR
ExecStart=/usr/bin/python3 $DIR/wol.py serve
Restart=on-failure
# izin khusus jaringan agar ping & arping bisa dipakai untuk cek status
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=$DIR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wol-panel >/dev/null 2>&1
systemctl restart wol-panel
echo "Selesai. Buka http://$(hostname -I | awk '{print $1}'):8080"
