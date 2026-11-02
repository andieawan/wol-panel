#!/bin/bash
# WOL Panel — perintah update yang boleh dijalankan panel di VM ini.
# Dipasang di /usr/local/sbin/wol-update dan dipanggil lewat SSH dengan kunci yang dikunci
# (forced command): panel hanya bisa menjalankan perintah di bawah ini, bukan shell bebas.
#
#   status       info OS, uptime, versi aplikasi
#   check        apt-get update + daftar paket yang bisa di-update + commit baru di repo
#   os-upgrade   apt-get upgrade (aman, tanpa menghapus paket)
#   app-update   menjalankan deploy/update.sh milik aplikasi
#   reboot       restart VM dalam 3 detik
#   self-update  perbarui skrip ini dari repo resmi (WOL_UPDATE_SRC), bukan dari panel
#
# Folder aplikasi diatur di /etc/wol-update.conf (APP_DIR=/var/www/...).
WOL_UPDATE_VERSION=3
set -uo pipefail
export LC_ALL=C DEBIAN_FRONTEND=noninteractive PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

APP_DIR=""
WOL_UPDATE_SRC="https://raw.githubusercontent.com/andieawan/wol-panel/main/vm-update.sh"
[ -f /etc/wol-update.conf ] && . /etc/wol-update.conf
CMD="${SSH_ORIGINAL_COMMAND:-${1:-status}}"
CMD="${CMD%% *}"

exec 9>/run/wol-update.lock
case "$CMD" in
  os-upgrade|app-update|reboot|self-update)
    flock -n 9 || { echo "error=Sedang ada proses update lain di VM ini."; exit 75; } ;;
esac

as_owner() {  # git sebagai pemilik folder aplikasi (hindari 'dubious ownership')
  local owner; owner="$(stat -c %U "$APP_DIR")"
  if [ "$owner" = root ]; then "$@"; else runuser -u "$owner" -- "$@"; fi
}

os_info() {
  . /etc/os-release
  echo "version=$WOL_UPDATE_VERSION"
  echo "host=$(hostname)"
  echo "os=${PRETTY_NAME:-Linux}"
  echo "kernel=$(uname -r)"
  echo "uptime=$(cut -d. -f1 /proc/uptime)"
  echo "disk=$(df -P / | awk 'NR==2{print $5}')"
  [ -f /var/run/reboot-required ] && echo "reboot=1" || echo "reboot=0"
}

app_info() {  # $1 = fetch untuk mengambil info commit terbaru dari GitHub
  if [ -z "$APP_DIR" ] || [ ! -d "$APP_DIR/.git" ]; then echo "app="; return; fi
  echo "app=$APP_DIR"
  [ -f "$APP_DIR/deploy/update.sh" ] && echo "app_script=1" || echo "app_script=0"
  echo "app_branch=$(as_owner git -C "$APP_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null)"
  echo "app_head=$(as_owner git -C "$APP_DIR" log -1 --format='%h|%ct|%s' 2>/dev/null)"
  if [ "${1:-}" = fetch ]; then
    local out
    if ! out="$(as_owner git -C "$APP_DIR" fetch --quiet 2>&1)"; then
      echo "app_error=git fetch gagal: $(echo "$out" | tail -1)"
    fi
  fi
  local behind
  behind="$(as_owner git -C "$APP_DIR" rev-list --count 'HEAD..@{u}' 2>/dev/null)" || behind="?"
  echo "app_behind=$behind"
  as_owner git -C "$APP_DIR" log --format='commit=%h|%ct|%s' -n 30 'HEAD..@{u}' 2>/dev/null
  local dirty
  dirty="$(as_owner git -C "$APP_DIR" status --porcelain --untracked-files=no -- . ':!vendor' 2>/dev/null | wc -l)"
  echo "app_dirty=$dirty"
}

case "$CMD" in
  status)
    os_info; app_info ;;
  check)
    os_info
    if ! out="$(apt-get update -qq 2>&1)"; then echo "apt_error=$(echo "$out" | tail -1)"; fi
    list="$(apt list --upgradable 2>/dev/null | tail -n +2 | grep -v '^Listing' || true)"
    echo "upgradable=$(printf '%s\n' "$list" | grep -c . || true)"
    echo "security=$(printf '%s\n' "$list" | grep -c -- '-security' || true)"
    # format: pkg=nama|versi lama|versi baru|sumber
    printf '%s\n' "$list" | grep . | head -300 |
      sed -E 's#^([^/]+)/([^ ]+) ([^ ]+) [^ ]+ \[upgradable from: ([^]]+)\]$#pkg=\1|\4|\3|\2#' | grep '^pkg=' || true
    app_info fetch
    echo "checked=$(date +%s)" ;;
  os-upgrade)
    echo "==> apt-get update"; apt-get update || exit 1
    echo; echo "==> apt-get upgrade"
    apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade || exit 1
    echo; echo "==> apt-get autoremove"; apt-get -y autoremove || true
    echo; [ -f /var/run/reboot-required ] && echo "PERHATIAN: VM perlu di-reboot agar pembaruan kernel/sistem berlaku."
    echo "Selesai." ;;
  app-update)
    [ -n "$APP_DIR" ] && [ -f "$APP_DIR/deploy/update.sh" ] || { echo "error=Skrip deploy/update.sh tidak ditemukan di APP_DIR='$APP_DIR'. Atur di /etc/wol-update.conf."; exit 2; }
    if [ "$(as_owner git -C "$APP_DIR" rev-list --count 'HEAD..@{u}' 2>/dev/null || echo 1)" = 0 ]; then
      as_owner git -C "$APP_DIR" fetch --quiet 2>/dev/null || true
    fi
    cd "$APP_DIR" && bash deploy/update.sh </dev/null ;;
  reboot)
    # ditunda 3 detik agar sesi SSH panel selesai rapi; berjalan di VM maupun container LXC
    if systemd-run --quiet --on-active=3 --unit="wol-reboot-$(date +%s)" systemctl reboot; then
      echo "VM restart dalam 3 detik."
    else
      echo "systemd-run gagal, memakai cara cadangan."
      nohup setsid sh -c 'sleep 3; systemctl reboot || reboot' >/dev/null 2>&1 &
      echo "VM restart dalam 3 detik."
    fi ;;
  self-update)
    # skrip diunduh VM sendiri dari repo resmi: panel tidak bisa menyisipkan kode
    echo "==> Mengunduh $WOL_UPDATE_SRC"
    self="$(readlink -f "$0")"; tmp="$(mktemp "$self.XXXXXX")"
    trap 'rm -f "$tmp"' EXIT
    curl -fsSL --max-time 60 "$WOL_UPDATE_SRC" -o "$tmp" || { echo "error: gagal mengunduh skrip baru."; exit 1; }
    bash -n "$tmp" || { echo "error: skrip baru tidak valid, dibatalkan."; exit 1; }
    nv="$(sed -n 's/^WOL_UPDATE_VERSION=\([0-9][0-9]*\)$/\1/p' "$tmp" | head -1)"
    [ -n "$nv" ] || { echo "error: versi skrip baru tidak terbaca, dibatalkan."; exit 1; }
    [ "$nv" -ge "$WOL_UPDATE_VERSION" ] || { echo "error: versi di repo ($nv) lebih lama dari yang terpasang ($WOL_UPDATE_VERSION), dibatalkan."; exit 1; }
    chown root:root "$tmp"; chmod 755 "$tmp"
    mv -f "$tmp" "$self"   # ganti file baru (inode baru) agar skrip yang sedang berjalan tidak rusak
    echo "wol-update diperbarui: versi $WOL_UPDATE_VERSION -> $nv" ;;
  *)
    echo "error=Perintah tidak dikenal: $CMD"; exit 64 ;;
esac
