#!/bin/bash
# WOL Panel — perintah update yang boleh dijalankan panel di VM ini.
# Dipasang di /usr/local/sbin/wol-update dan dipanggil lewat SSH dengan kunci yang dikunci
# (forced command): panel hanya bisa menjalankan perintah di bawah ini, bukan shell bebas.
#
#   status       info OS, uptime, versi aplikasi
#   health       cek aplikasi hidup: layanan (nginx, php-fpm, mariadb, …) + halaman /up aplikasi Laravel
#   check        apt-get update + daftar paket yang bisa di-update + commit baru di repo
#   os-upgrade   apt-get upgrade (aman, tanpa menghapus paket)
#   app-update   menjalankan deploy/update.sh milik aplikasi
#   reboot       restart VM dalam 3 detik
#   self-update  perbarui skrip ini dari repo resmi (WOL_UPDATE_SRC), bukan dari panel
#   app-install KODE  pasang aplikasi sekolah dari katalog di bawah — HANYA di VM yang masih baru & kosong (fresh=1)
#
# Folder aplikasi diatur di /etc/wol-update.conf (APP_DIR=/var/www/...).
WOL_UPDATE_VERSION=7
set -uo pipefail
export LC_ALL=C DEBIAN_FRONTEND=noninteractive PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

APP_DIR=""
TERM_USER=""
WOL_UPDATE_SRC="https://raw.githubusercontent.com/andieawan/wol-panel/main/vm-update.sh"
DOMAIN_BASE="smkibupakusari.sch.id"   # domain sekolah untuk app-install (bisa diganti di /etc/wol-update.conf)
PROXY_IP="192.168.10.10"              # NPMplus
FRESH_DAYS=7                          # "Pasang aplikasi" hanya untuk VM yang dibuat <= sekian hari lalu
[ -f /etc/wol-update.conf ] && . /etc/wol-update.conf

# Migrasi dari versi lama (tanpa TERM_USER): terminal web pindah dari root ke user biasa,
# root tetap bisa lewat sudo -i. Berjalan sekali, otomatis setelah "Perbarui wol-update".
if [ -z "$TERM_USER" ] && [ "$(id -u)" = 0 ] && [ -w /etc/wol-update.conf ]; then
  TERM_USER="$(awk -F: '$3>=1000 && $3<60000 && $7 !~ /(nologin|false)$/ {print $1; exit}' /etc/passwd)"
  [ -n "$TERM_USER" ] || TERM_USER=root
  if [ "$TERM_USER" != root ] && grep -q 'wol-panel-terminal$' /root/.ssh/authorized_keys 2>/dev/null; then
    th="$(getent passwd "$TERM_USER" | cut -d: -f6)"; tg="$(id -gn "$TERM_USER")"
    install -d -m 700 -o "$TERM_USER" -g "$tg" "$th/.ssh"; touch "$th/.ssh/authorized_keys"
    sed -i '/wol-panel-terminal$/d' "$th/.ssh/authorized_keys"
    grep 'wol-panel-terminal$' /root/.ssh/authorized_keys >> "$th/.ssh/authorized_keys"
    chown "$TERM_USER:$tg" "$th/.ssh/authorized_keys"; chmod 600 "$th/.ssh/authorized_keys"
    sed -i '/wol-panel-terminal$/d' /root/.ssh/authorized_keys
  fi
  echo "TERM_USER=\"$TERM_USER\"" >> /etc/wol-update.conf
fi

CMD="${SSH_ORIGINAL_COMMAND:-${*:-status}}"
ARG="${CMD#* }"; [ "$ARG" = "$CMD" ] && ARG=""
CMD="${CMD%% *}"
ARG="${ARG%% *}"

exec 9>/run/wol-update.lock
case "$CMD" in
  os-upgrade|app-update|reboot|self-update|app-install)
    flock -n 9 || { echo "error=Sedang ada proses update lain di VM ini."; exit 75; } ;;
esac

as_owner() {  # git sebagai pemilik folder aplikasi (hindari 'dubious ownership')
  local owner; owner="$(stat -c %U "$APP_DIR")"
  if [ "$owner" = root ]; then "$@"; else runuser -u "$owner" -- "$@"; fi
}

os_info() {
  . /etc/os-release
  echo "version=$WOL_UPDATE_VERSION"
  echo "term_user=$TERM_USER"
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

# Katalog aplikasi yang boleh dipasang lewat panel (kode -> repo|folder|pemilik kode|subdomain).
# Repo & folder ditentukan DI SINI (bukan oleh panel): kunci panel hanya bisa memilih kode.
# pemilik "user" = Pusat & Jurnal: kode di-clone sebagai TERM_USER (skrip pasangnya menolak folder milik root).
app_catalog() {
  case "$1" in
    pusat)      echo "pusat-sekolah|/var/www/pusat-sekolah|user|pusat" ;;
    web)        echo "web-pusat|/var/www/web-pusat|root|@" ;;
    jurnal)     echo "jurnal-pusat|/var/www/jurnal|user|jurnal" ;;
    bk)         echo "bk-pusat|/var/www/bk-pusat|root|bk" ;;
    tu)         echo "tu-pusat|/var/www/tu-pusat|root|tu" ;;
    pkl)        echo "pkl-pusat|/var/www/pkl-pusat|root|pkl" ;;
    tanggungan) echo "tanggungan-pusat|/var/www/tanggungan|root|tanggungan" ;;
    backup)     echo "backup-master|/var/www/backup-master|root|-" ;;
    *) return 1 ;;
  esac
}

vm_age_days() {  # umur VM dari waktu lahir /etc/machine-id (dibuat saat OS dipasang)
  local t; t="$(stat -c %W /etc/machine-id 2>/dev/null)"
  { [ -z "$t" ] || [ "$t" = 0 ] || [ "$t" = "-" ]; } && t="$(stat -c %Y /etc/machine-id 2>/dev/null || echo 0)"
  echo $(( ($(date +%s) - t) / 86400 ))
}

is_fresh() {  # VM baru (<= FRESH_DAYS hari) dan belum ada aplikasi apa pun
  [ -z "$APP_DIR" ] || return 1
  [ "$(vm_age_days)" -le "$FRESH_DAYS" ] || return 1
  local d
  for d in /var/www/*/ /root/wol-panel/ /opt/wol-panel/; do
    [ -d "$d" ] || continue
    case "$d" in /var/www/html/) continue ;; esac
    return 1
  done
  return 0
}

fresh_info() {
  echo "vm_age_days=$(vm_age_days)"
  if is_fresh; then echo "fresh=1"; else echo "fresh=0"; fi
}

app_install() {
  local info repo dir owner sub url domain
  info="$(app_catalog "$1")" || { echo "error=Kode aplikasi tidak dikenal: $1"; exit 64; }
  is_fresh || { echo "error=Pasang aplikasi hanya untuk VM baru (<= $FRESH_DAYS hari) yang belum berisi aplikasi."; exit 65; }
  IFS='|' read -r repo dir owner sub <<<"$info"
  url="https://github.com/andieawan/$repo.git"
  case "$sub" in "@") domain="$DOMAIN_BASE" ;; "-") domain="" ;; *) domain="$sub.$DOMAIN_BASE" ;; esac
  echo "==> Memasang $1 dari $url ke $dir"
  apt-get update -qq && apt-get install -y -qq git curl ca-certificates >/dev/null || { echo "error: gagal memasang git."; exit 1; }
  install -d -m 755 /var/www
  if [ "$owner" = user ]; then
    [ -n "$TERM_USER" ] && [ "$TERM_USER" != root ] || { echo "error: VM ini belum punya user biasa (skrip pasang $1 menolak folder milik root). Buat user lalu jalankan ulang perintah pasang wol-update."; exit 1; }
    install -d -o "$TERM_USER" -g "$(id -gn "$TERM_USER")" "$dir"
    runuser -u "$TERM_USER" -- git clone --quiet "$url" "$dir" || { echo "error: git clone gagal."; exit 1; }
  else
    git clone --quiet "$url" "$dir" || { echo "error: git clone gagal."; exit 1; }
  fi
  echo "==> Menjalankan deploy/install.sh (beberapa menit)"
  cd "$dir"
  if [ "$1" = backup ]; then
    LOKASI="Utama (Proxmox)" bash deploy/install.sh </dev/null || exit 1
  else
    DOMAIN="$domain" APP_URL="https://$domain" PROXY_IP="$PROXY_IP" bash deploy/install.sh </dev/null || exit 1
  fi
  sed -i '/^APP_DIR=/d' /etc/wol-update.conf; echo "APP_DIR=\"$dir\"" >> /etc/wol-update.conf
  echo; echo "Selesai: $1 terpasang di $dir.${domain:+ Alamat: https://$domain (atur Proxy Host di NPMplus).}"
}

app_health() {  # keluaran health_*=… ; health_ok=1 bila semua layanan aktif dan halaman aplikasi menjawab 200
  local ok=1 svc=() u st url host code=""
  for u in nginx apache2 mariadb mysql wol-panel $(systemctl list-unit-files --type=service --no-legend 'php*-fpm.service' 2>/dev/null | awk '{print $1}'); do
    u="${u%.service}"
    systemctl list-unit-files --no-legend "$u.service" 2>/dev/null | grep -q enabled || continue
    st="$(systemctl is-active "$u" 2>/dev/null)"; svc+=("$u:$st")
    [ "$st" = active ] || ok=0
  done
  echo "health_svc=$(IFS=,; echo "${svc[*]}")"
  if [ -n "$APP_DIR" ] && [ -f "$APP_DIR/artisan" ]; then
    url="$(sed -n 's/^APP_URL=//p' "$APP_DIR/.env" 2>/dev/null | tail -1 | tr -d "\"' \r")"
    host="${url#*://}"; host="${host%%/*}"; host="${host%%:*}"
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H "Host: ${host:-localhost}" http://127.0.0.1/up 2>/dev/null)"
    echo "health_url=http://${host:-localhost}/up"
  elif [ -n "$APP_DIR" ] && [ -f "$APP_DIR/wol.py" ]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:8080/login 2>/dev/null)"
    echo "health_url=http://127.0.0.1:8080/login"
  fi
  if [ -n "$code" ]; then
    echo "health_http=$code"
    [ "$code" = 200 ] || ok=0
  fi
  echo "health_ok=$ok"
}

case "$CMD" in
  status)
    os_info; fresh_info; app_info ;;
  health)
    echo "version=$WOL_UPDATE_VERSION"; app_health ;;
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
    fresh_info
    app_health
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
  app-install)
    app_install "$ARG" ;;
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
