#!/usr/bin/env bash
# Pasang WOL Panel sebagai layanan systemd (Debian/Ubuntu, termasuk container LXC Proxmox).
set -e
DIR=/opt/wol-panel
[ "$(id -u)" = 0 ] || { echo "Jalankan sebagai root: sudo bash install.sh"; exit 1; }

apt-get update -qq && apt-get install -y -qq python3 iputils-ping >/dev/null
id wolpanel >/dev/null 2>&1 || useradd --system --home "$DIR" --shell /usr/sbin/nologin wolpanel
mkdir -p "$DIR"
install -m 755 "$(dirname "$0")/wol.py" "$DIR/wol.py"

if [ ! -f "$DIR/config.json" ]; then
  (cd "$DIR" && python3 wol.py init && python3 wol.py adddevice)
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
