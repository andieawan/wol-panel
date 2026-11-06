#!/usr/bin/env bash
# Cadangkan data WOL Panel:  sudo wol-panel-backup   (atau dari repo: sudo bash deploy/backup.sh)
# install.sh memasangnya di /usr/local/sbin/wol-panel-backup dan timer harian wol-panel-backup (02:00). Hasil:
#   /var/backups/wol-panel/wol_YYYY-MM-DD_HHMM.tar.gz  (disimpan 14 hari; ditarik Backup Master, templat "WOL Panel")
# Isi: config.json (akun, komputer, kunci agen), vm.json, scan.json, wallpapers/, ssh/ (kunci SSH panel ke VM).
# Rekaman terminal (vmlogs/) tidak ikut. Memulihkan: lihat README bagian "Backup & pemulihan".
set -euo pipefail
DIR="${WOL_DIR:-/opt/wol-panel}"
OUT="${WOL_BACKUP_DIR:-/var/backups/wol-panel}"
SIMPAN_HARI="${WOL_BACKUP_DAYS:-14}"
[ "$(id -u)" -eq 0 ] || { echo "Jalankan dengan sudo." >&2; exit 1; }
[ -f "$DIR/config.json" ] || { echo "GAGAL: $DIR/config.json tidak ada." >&2; exit 1; }

isi=()
for f in config.json vm.json scan.json wallpapers ssh; do [ -e "$DIR/$f" ] && isi+=("$f"); done
install -d -m 700 "$OUT"
nama="wol_$(date +%Y-%m-%d_%H%M).tar.gz"
tmp="$(mktemp "$OUT/.$nama.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
umask 077
tar -czf "$tmp" -C "$DIR" "${isi[@]}"
tar -tzf "$tmp" config.json >/dev/null   # pastikan arsip terbaca & berisi config.json
chmod 600 "$tmp"
mv -f "$tmp" "$OUT/$nama"
trap - EXIT
find "$OUT" -maxdepth 1 -name 'wol_*.tar.gz' -mtime "+$SIMPAN_HARI" -delete
echo "Backup: $OUT/$nama ($(du -h "$OUT/$nama" | cut -f1))"
