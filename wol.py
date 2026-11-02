#!/usr/bin/env python3
"""
WOL Panel - panel web ringan untuk menghidupkan komputer lewat Wake-on-LAN.
Hanya memakai pustaka standar Python 3 (tanpa pip install).

Semua pengaturan (perangkat, pengguna, pengaturan umum) dikelola dari web,
menu "Pengaturan" (khusus peran admin).

Perintah terminal:
  python3 wol.py init              buat config.json + akun admin pertama
  python3 wol.py users             tampilkan daftar akun
  python3 wol.py resetpw <nama>    reset password / buat admin jika lupa password
  python3 wol.py list              tampilkan daftar komputer + status
  python3 wol.py wake <id>         kirim magic packet dari terminal
  python3 wol.py serve             jalankan panel web
"""
import base64
import fcntl
import fnmatch
import getpass
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import signal
import struct
import shutil
import socket
import subprocess
import sys
import termios
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlencode, urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("WOL_CONFIG", os.path.join(BASE, "config.json"))
LOG_PATH = os.environ.get("WOL_LOG", os.path.join(BASE, "wol.log"))
COOKIE = "wol_session"
CFG = {}
CFG_LOCK = threading.Lock()
LOG_LOCK = threading.Lock()
FAILS = {}  # ip -> [waktu] percobaan login gagal
FAIL_LIMIT, FAIL_WINDOW = 5, 600
WAKE_COOLDOWN = {}  # id perangkat -> waktu terakhir dikirim
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
USER_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
DEFAULT_REMOTE = "https://remotedesktop.google.com/access"
AGENT_TEMPLATE = os.path.join(BASE, "windows-agent.ps1")
AGENT_PORT = 8765
AGENT_TOKENS = {}  # token sekali-pakai untuk unduh pemasang agen -> (id perangkat, kedaluwarsa)
AGENT_TOKEN_TTL = 900
SHUTDOWN_DELAY = 10  # detik peringatan di layar sebelum komputer mati
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


# ---------------------------------------------------------------- konfigurasi
def migrate(cfg):
    """Menyesuaikan config versi lama (password berupa string) ke format baru."""
    for u, v in list(cfg.get("users", {}).items()):
        if isinstance(v, str):
            cfg["users"][u] = {"hash": v, "role": "admin", "sv": 0}
    cfg.setdefault("devices", [])
    cfg.setdefault("trust_proxy", False)
    cfg.setdefault("session_hours", 12)
    cfg.setdefault("app_rules", [])
    cfg.setdefault("scan_minutes", 60)
    cfg.setdefault("vms", [])
    cfg.setdefault("vm_check_hours", 6)
    return cfg


def load_config():
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return migrate(json.load(f))


def save_config(cfg):
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    os.chmod(tmp, 0o600)
    if os.geteuid() == 0:  # dijalankan root (mis. resetpw): pertahankan pemilik agar layanan tetap bisa membaca
        try:
            st = os.stat(CONFIG_PATH if os.path.exists(CONFIG_PATH) else BASE)
            os.chown(tmp, st.st_uid, st.st_gid)
        except OSError:
            pass
    os.replace(tmp, CONFIG_PATH)


def hash_password(pw, iterations=200_000):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def check_password(pw, stored):
    try:
        _, it, salt, dk = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it))
        return hmac.compare_digest(calc.hex(), dk)
    except Exception:
        return False


def normalize_mac(mac):
    h = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    if len(h) != 12:
        raise ValueError(f"MAC address tidak valid: {mac!r}")
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)).upper()


def slugify(text):
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")[:32] or "pc"


def is_admin(user):
    return CFG["users"].get(user, {}).get("role") == "admin"


def admin_count():
    return sum(1 for u in CFG["users"].values() if u.get("role") == "admin")


# ------------------------------------------------------------- wake-on-lan
def magic_packet(mac):
    return b"\xff" * 6 + bytes.fromhex(normalize_mac(mac).replace(":", "")) * 16


def send_wol(dev):
    pkt = magic_packet(dev["mac"])
    # kirim ke broadcast subnet DAN broadcast umum: jika netmask server berbeda,
    # broadcast subnet bisa dianggap alamat biasa dan paket tidak pernah keluar
    targets = []
    for t in (dev.get("broadcast"), "255.255.255.255"):
        if t and t not in targets:
            targets.append(t)
    ports = [int(dev.get("port", 9))]
    if ports[0] == 9:
        ports.append(7)  # sebagian kartu jaringan hanya mendengar port 7
    sent, errors = 0, []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for _ in range(3):
            for t in targets:
                for p in ports:
                    try:
                        s.sendto(pkt, (t, p))
                        sent += 1
                    except OSError as e:
                        errors.append(f"{t}: {e.strerror or e}")
            time.sleep(0.1)
    if not sent:
        raise OSError("; ".join(sorted(set(errors))))
    return targets


MAC_RE = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")


def check_port(ip, port):
    try:
        socket.create_connection((ip, int(port)), timeout=0.8).close()
        return True
    except OSError:
        return False


def check_arp(ip):
    """Kirim ARP request (hanya untuk satu jaringan/subnet yang sama).
    Windows tetap menjawab ARP walau ping diblokir firewall.
    Hasil: (True/False/None, mac_yang_menjawab). None = arping tidak tersedia/gagal jalan."""
    exe = shutil.which("arping")
    if not exe:
        return None, None
    try:
        r = subprocess.run([exe, "-c", "1", "-w", "1", ip], capture_output=True, text=True, timeout=4)
    except Exception:
        return None, None
    m = MAC_RE.search(r.stdout)
    if m:
        return True, normalize_mac(m.group(1))
    if "Operation not permitted" in r.stderr or "permission" in r.stderr.lower():
        return None, None
    return False, None


def check_ping(ip):
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, text=True, timeout=3)
        if r.returncode == 0:
            return True
        if "not permitted" in r.stderr or "permission" in r.stderr.lower():
            return None
        return False
    except Exception:
        return None


def is_online(dev):
    ip = dev.get("ip")
    if not ip:
        return None
    if any(check_port(ip, p) for p in dev.get("check_ports", [])):
        return True
    arp, _ = check_arp(ip)
    if arp:
        return True
    return bool(check_ping(ip))


def diagnose(dev):
    ip = dev.get("ip")
    if not ip:
        return "IP komputer belum diisi, status tidak bisa dicek."
    out = []
    for p in dev.get("check_ports", []):
        out.append(f"Port {p}: {'terbuka' if check_port(ip, p) else 'tertutup'}")
    arp, mac = check_arp(ip)
    if arp is None:
        out.append("ARP: arping belum terpasang / tidak diizinkan (jalankan ulang install.sh)")
    elif arp:
        cocok = mac == normalize_mac(dev["mac"])
        out.append(f"ARP: dijawab oleh {mac} ({'MAC cocok' if cocok else 'MAC TIDAK cocok — cek IP/MAC yang diisi'})")
    else:
        out.append("ARP: tidak ada jawaban (komputer mati, IP salah, atau beda jaringan)")
    pg = check_ping(ip)
    out.append("Ping: " + {True: "menjawab", False: "tidak menjawab (wajar jika diblokir Windows Firewall)",
                            None: "tidak diizinkan di server (jalankan ulang install.sh)"}[pg])
    if dev.get("agent_secret"):
        ok, why = agent_ping(dev)
        if ok:
            v, t = agent_info(dev), template_version()
            if v:
                set_agent_version(dev, v)
            state = ("terbaru" if v == t else "perlu pasang ulang sekali" if v < MIN_UPDATABLE else f"versi {t} tersedia — klik Perbarui agen") if v else ""
            out.append(f"Agen: aktif, versi {v or '?'}" + (f" ({state})" if state else ""))
        else:
            out.append("Agen: " + why)
    return f"Tes {dev['name']} ({ip}) — " + " · ".join(out)


# ------------------------------------------------------- agen Windows
def local_ip_for(target):
    """IP server ini yang dipakai untuk menjangkau target (dipakai agen sebagai IP panel yang diizinkan)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((target, 9))
        return s.getsockname()[0]


def agent_url(dev, path):
    return f"http://{dev['ip']}:{int(dev.get('agent_port', AGENT_PORT))}{path}"


def agent_error(e):
    if isinstance(e, urllib.error.HTTPError):
        if e.code == 403:
            return "agen menolak IP panel (IP panel berubah?) — pasang ulang agen"
        if e.code == 401:
            body = e.read().decode("utf-8", "replace").strip()
            if body == "clock":
                return "jam panel dan komputer selisih lebih dari 2 menit — samakan jamnya"
            return "kunci agen tidak cocok — pasang ulang agen"
        return f"agen menjawab error {e.code}"
    return "agen tidak merespons (komputer mati, atau agen belum terpasang)"


def agent_ping(dev):
    try:
        with NO_PROXY.open(agent_url(dev, "/ping"), timeout=2) as r:
            return r.read().strip() == b"ok", "jawaban tidak dikenal"
    except Exception as e:
        return False, agent_error(e)


def agent_shutdown(dev, user, delay=SHUTDOWN_DELAY):
    ts, nonce = str(int(time.time())), secrets.token_hex(16)
    by = re.sub(r"[^A-Za-z0-9._-]", "", user)[:32]
    msg = f"shutdown|{ts}|{nonce}|{delay}|{by}"
    sig = hmac.new(dev["agent_secret"].encode(), msg.encode(), hashlib.sha256).hexdigest()
    req = urllib.request.Request(agent_url(dev, "/shutdown"), data=b"", method="POST", headers={
        "X-WOL-Time": ts, "X-WOL-Nonce": nonce, "X-WOL-Delay": str(delay), "X-WOL-User": by, "X-WOL-Signature": sig})
    with NO_PROXY.open(req, timeout=5) as r:
        return r.read().strip() == b"ok"


class AgentOld(Exception):
    pass


def agent_cmd(dev, user, payload, timeout=60):
    """Perintah JSON bertanda tangan ke agen (pindai / uninstall). Agen v1 menjawab 404 -> AgentOld."""
    body = json.dumps(payload, separators=(",", ":"))
    ts, nonce = str(int(time.time())), secrets.token_hex(16)
    by = re.sub(r"[^A-Za-z0-9._-]", "", user)[:32]
    sig = hmac.new(dev["agent_secret"].encode(), f"cmd|{ts}|{nonce}|{hashlib.sha256(body.encode()).hexdigest()}|{by}".encode(),
                   hashlib.sha256).hexdigest()
    req = urllib.request.Request(agent_url(dev, "/cmd"), data=body.encode(), method="POST", headers={
        "Content-Type": "application/json", "X-WOL-Time": ts, "X-WOL-Nonce": nonce, "X-WOL-User": by, "X-WOL-Signature": sig})
    try:
        with NO_PROXY.open(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8-sig"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise AgentOld() from e
        raise


# ------------------------------------------------------- pemindai aplikasi
SCAN_PATH = os.environ.get("WOL_SCAN", os.path.join(BASE, "scan.json"))
SCANS = {}            # id perangkat -> {"time", "apps", "error", "auto": [catatan hapus otomatis]}
SCAN_LOCK = threading.Lock()
SCAN_BUSY = set()     # perangkat yang sedang dipindai / di-uninstall
AUTO_FAIL = {}        # (perangkat, id aplikasi) -> waktu gagal hapus otomatis terakhir
AUTO_RETRY = 6 * 3600
# tidak pernah dihapus otomatis walau cocok aturan (tetap bisa di-uninstall manual)
PROTECTED = re.compile(r"wol panel|visual c\+\+|\.net|windows|driver|intel|nvidia|realtek|webview|microsoft edge|"
                       r"microsoft office|microsoft 365|update health|chrome remote desktop", re.I)


SOURCES = (("luar", "Dari luar"), ("store", "Store"), ("bawaan", "Bawaan"))
SYSTEM_NAME = re.compile(r"visual c\+\+|\.net|windows|driver|webview|microsoft edge|onedrive|update health|"
                         r"runtime|redistributable|directx|vcredist|chipset|bluetooth|audio|graphics", re.I)
OEM_PUBLISHER = re.compile(r"^(microsoft|intel|realtek|nvidia|amd|advanced micro devices|synaptics|elan|dolby|waves|"
                           r"lenovo|hp |hp inc|hewlett|dell|asus|asustek|acer|msi|micro-star|qualcomm|mediatek|broadcom)", re.I)


def app_source(app, osdate=""):
    """Kelompok aplikasi: 'bawaan' (ikut Windows/pabrikan), 'store' (dari Microsoft Store), 'luar' (installer dari luar)."""
    name, pub = app.get("name") or "", (app.get("publisher") or "").strip()
    if app.get("kind") == "store":
        if app.get("provisioned"):
            return "bawaan"
        if "provisioned" not in app and pub.lower().startswith("microsoft"):  # data agen lama
            return "bawaan"
        return "store"
    if SYSTEM_NAME.search(name) or OEM_PUBLISHER.match(pub):
        return "bawaan"
    d = app.get("date") or ""
    if osdate and re.fullmatch(r"\d{8}", d) and re.fullmatch(r"\d{8}", osdate):
        try:
            if abs(time.mktime(time.strptime(d, "%Y%m%d")) - time.mktime(time.strptime(osdate, "%Y%m%d"))) <= 2 * 86400:
                return "bawaan"
        except ValueError:
            pass
    return "luar"


def user_installed(app):
    """Terpasang di profil satu akun (tanpa hak admin) — biasanya dipasang sendiri oleh siswa."""
    return app.get("kind") != "store" and str(app.get("id", "")).startswith("U:")


def note_failure(dev_id, app, ok, msg, by):
    with SCAN_LOCK:
        s = SCANS.get(dev_id)
        if s is None:
            return
        failed = s.setdefault("failed", {})
        if ok:
            failed.pop(app["id"], None)
        elif app["id"] not in s.get("dismissed", []):
            failed[app["id"]] = {"name": app.get("name", app["id"]), "msg": msg, "time": int(time.time()), "by": by}
        save_scans()


def failures():
    out = []
    for d in CFG.get("devices", []):
        s = SCANS.get(d["id"]) or {}
        present = {a.get("id") for a in s.get("apps", [])}
        for aid, f in (s.get("failed") or {}).items():
            if aid in present:
                out.append((d, aid, f))
    return sorted(out, key=lambda x: -x[2]["time"])


def load_scans():
    global SCANS
    try:
        with open(SCAN_PATH, encoding="utf-8") as f:
            SCANS = json.load(f)
    except (FileNotFoundError, ValueError):
        SCANS = {}


def save_scans():
    tmp = SCAN_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(SCANS, f, ensure_ascii=False)
    os.replace(tmp, SCAN_PATH)


def rule_regex(pattern):
    p = pattern.strip().lower()
    if "*" not in p and "?" not in p:
        p = f"*{p}*"
    return re.compile(fnmatch.translate(p), re.I)


def match_rule(app):
    for r in CFG.get("app_rules", []):
        if rule_regex(r["pattern"]).match(app.get("name", "")):
            return r
    return None


def flagged(dev_id):
    s = SCANS.get(dev_id) or {}
    return [(a, r) for a in s.get("apps", []) for r in [match_rule(a)] if r]


def scan_device(dev, user="otomatis", auto=True):
    """Pindai satu komputer, simpan hasilnya, lalu jalankan aturan hapus otomatis. Mengembalikan pesan ringkas."""
    if dev["id"] in SCAN_BUSY:
        return "Komputer ini sedang dipindai."
    SCAN_BUSY.add(dev["id"])
    try:
        try:
            res = agent_cmd(dev, user, {"action": "scan"}, timeout=90)
            apps = sorted(res.get("apps") or [], key=lambda a: (a.get("name") or "").lower())
            entry = {"time": int(time.time()), "apps": apps, "error": None, "osdate": str(res.get("osdate") or "")}
            if res.get("version"):
                set_agent_version(dev, int(res["version"]))
        except AgentOld:
            set_agent_version(dev, 1)
            entry = {"time": int(time.time()), "apps": (SCANS.get(dev["id"]) or {}).get("apps", []),
                     "error": "Agen versi lama — klik Agen di Pengaturan lalu jalankan ulang perintahnya di komputer ini."}
        except Exception as e:
            entry = {"time": int(time.time()), "apps": (SCANS.get(dev["id"]) or {}).get("apps", []), "error": agent_error(e)}
        with SCAN_LOCK:
            old = SCANS.get(dev["id"]) or {}
            present = {a.get("id") for a in entry["apps"]}
            entry["auto"] = old.get("auto", [])
            entry.setdefault("osdate", old.get("osdate", ""))
            # kegagalan / abaikan untuk aplikasi yang sudah tidak ada dibuang
            entry["failed"] = {k: v for k, v in (old.get("failed") or {}).items() if k in present}
            entry["dismissed"] = [k for k in old.get("dismissed", []) if k in present]
            SCANS[dev["id"]] = entry
            save_scans()
        if entry["error"]:
            return f"Gagal memindai {dev['name']}: {entry['error']}"
        n_flag = len(flagged(dev["id"]))
        removed = run_auto_rules(dev) if auto else []
        msg = f"{dev['name']}: {len(entry['apps'])} aplikasi, {n_flag} cocok aturan."
        if removed:
            msg += f" Dihapus otomatis: {', '.join(removed)}."
        return msg
    finally:
        SCAN_BUSY.discard(dev["id"])


def uninstall_app(dev, app_id, user, mode="uninstall"):
    try:
        r = agent_cmd(dev, user, {"action": "uninstall", "id": app_id}, timeout=240)
    except AgentOld:
        return False, "Agen versi lama — pasang ulang agen di komputer ini."
    except Exception as e:
        return False, agent_error(e)  # komputer tidak terjangkau: bukan kegagalan uninstall
    ok, msg = bool(r.get("ok")), str(r.get("msg") or "")
    short = msg if len(msg) <= 90 else msg[:90].rsplit(" ", 1)[0] + "…"
    write_log(user, mode if ok else mode + "-gagal", f"{dev['id']}:{short}", "-")
    app = next((a for a in (SCANS.get(dev["id"]) or {}).get("apps", []) if a.get("id") == app_id), {"id": app_id})
    note_failure(dev["id"], app, ok, msg, user)
    if ok:  # hapus dari hasil pindai tanpa menunggu pindai ulang
        with SCAN_LOCK:
            s = SCANS.get(dev["id"])
            if s:
                s["apps"] = [a for a in s["apps"] if a.get("id") != app_id]
                save_scans()
    return ok, msg


def run_auto_rules(dev):
    removed = []
    for app, rule in flagged(dev["id"]):
        if not rule.get("auto") or PROTECTED.search(app.get("name", "")):
            continue
        if app["id"] in (SCANS.get(dev["id"]) or {}).get("dismissed", []):
            continue
        key = (dev["id"], app["id"])
        if time.time() - AUTO_FAIL.get(key, 0) < AUTO_RETRY:
            continue
        ok, msg = uninstall_app(dev, app["id"], "otomatis", "hapus-otomatis")
        with SCAN_LOCK:
            s = SCANS.get(dev["id"])
            if s is not None:
                s.setdefault("auto", []).append({"time": int(time.time()), "name": app["name"], "ok": ok, "msg": msg})
                s["auto"] = s["auto"][-20:]
                save_scans()
        if ok:
            removed.append(app["name"])
        else:
            AUTO_FAIL[key] = time.time()
    return removed


def scan_all(user="otomatis", only_due=False):
    minutes = int(CFG.get("scan_minutes", 60))
    for dev in list(CFG.get("devices", [])):
        if not dev.get("agent_secret") or not dev.get("ip"):
            continue
        last = (SCANS.get(dev["id"]) or {}).get("time", 0)
        if only_due and time.time() - last < minutes * 60:
            continue
        if not agent_ping(dev)[0]:  # komputer mati / agen belum jalan: lewati, coba lagi nanti
            continue
        try:
            scan_device(dev, user)
        except Exception as e:
            print("pindai gagal", dev["id"], e, file=sys.stderr)


def scanner_loop():
    while True:
        time.sleep(60)
        try:
            maintain_agents()
        except Exception as e:
            print("pembaruan agen:", e, file=sys.stderr)
        try:
            check_all_vms()
        except Exception as e:
            print("cek VM:", e, file=sys.stderr)
        try:
            if int(CFG.get("scan_minutes", 60)) > 0:
                scan_all(only_due=True)
        except Exception as e:
            print("pemindai otomatis:", e, file=sys.stderr)


# ------------------------------------------------------- versi & pembaruan agen
MIN_UPDATABLE = 4     # agen mulai versi ini bisa diperbarui dari panel


def template_version():
    try:
        with open(AGENT_TEMPLATE, encoding="utf-8") as f:
            m = re.search(r"^\$AgentVersion = (\d+)", f.read(), re.M)
        return int(m.group(1)) if m else 0
    except OSError:
        return 0


def agent_code(dev):
    """Kode agen saja (isi here-string $AgentCode dari pemasang), sudah terisi kunci/port/IP panel."""
    script = agent_script(dev)
    m = re.search(r"\$AgentCode = @'\r?\n(.*?)\r?\n'@", script, re.S)
    return m.group(1) if m else ""


def set_agent_version(dev, v):
    if dev.get("agent_version") != v:
        with CFG_LOCK:
            dev["agent_version"] = v
            save_config(CFG)


def agent_info(dev):
    """Versi agen. 1 = belum punya perintah JSON, 3 = punya pindai tapi belum bisa diperbarui dari panel."""
    try:
        r = agent_cmd(dev, "panel", {"action": "info"}, timeout=10)
        return int(r.get("version") or 0)
    except AgentOld:
        return 1
    except urllib.error.HTTPError as e:
        return 3 if e.code == 400 else None
    except Exception:
        return None


def agent_update(dev, user="otomatis"):
    target = template_version()
    code = agent_code(dev)
    if not code:
        return False, "Template agen di server tidak terbaca."
    try:
        r = agent_cmd(dev, user, {"action": "update", "code": code}, timeout=30)
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read().decode("utf-8-sig")).get("msg") or agent_error(e)
        except Exception:
            msg = agent_error(e)
        return False, msg
    except Exception as e:
        return False, agent_error(e)
    if not r.get("ok"):
        return False, str(r.get("msg") or "Pembaruan ditolak agen.")
    for _ in range(30):  # tunggu agen dimulai ulang
        time.sleep(2)
        v = agent_info(dev)
        if v == target:
            set_agent_version(dev, v)
            write_log(user, "perbarui-agen", f"{dev['id']}:versi {v}", "-")
            return True, f"Agen {dev['name']} diperbarui ke versi {v}."
    v = agent_info(dev)
    if v:
        set_agent_version(dev, v)
    return False, "Agen tidak kembali dengan versi baru (versi lama dipulihkan otomatis bila gagal). Lihat agent.log di komputer itu."


def maintain_agent(dev):
    if not dev.get("agent_secret") or not dev.get("ip") or not agent_ping(dev)[0]:
        return
    target = template_version()
    v = dev.get("agent_version")
    if v is None or v < target:
        v = agent_info(dev) or v
        if v:
            set_agent_version(dev, v)


def maintain_agents():
    devs = [d for d in list(CFG.get("devices", [])) if d.get("agent_secret") and d.get("ip")]
    if devs:
        with ThreadPoolExecutor(max_workers=min(16, len(devs))) as ex:
            list(ex.map(maintain_agent, devs))


def agent_badge(dev):
    if not dev.get("agent_secret"):
        return ""
    v, t = dev.get("agent_version"), template_version()
    if v is None:
        return ' <span class="tag">Agen</span>'
    if v < MIN_UPDATABLE:
        return f' <span class="tag warn" title="Agen ini belum bisa diperbarui dari panel">Agen v{v} · pasang ulang sekali</span>'
    if v < t:
        return f' <span class="tag warn">Agen v{v} · ada versi {t}</span>'
    return f' <span class="tag ok">Agen v{v}</span>'


# ------------------------------------------------------- update VM (SSH terkunci)
VM_TEMPLATE = os.path.join(BASE, "vm-update.sh")
SSH_DIR = os.path.join(BASE, "ssh")
SSH_KEY = os.path.join(SSH_DIR, "id_ed25519")
VM_STATE_PATH = os.environ.get("WOL_VMSTATE", os.path.join(BASE, "vm.json"))
VM_LOG_DIR = os.path.join(BASE, "vmlogs")
VMSTATE = {}          # id VM -> {"checked", "data", "error"}
VM_LOCK = threading.Lock()
VM_JOBS = {}          # id VM -> {"action", "start", "end", "rc", "by"}
VM_TOKENS = {}        # token pasang -> (id VM, kedaluwarsa)
VM_ACTIONS = {"check": "Cek pembaruan", "os-upgrade": "Update OS", "app-update": "Update aplikasi", "reboot": "Reboot",
              "self-update": "Perbarui wol-update"}
VM_SELF_UPDATE_MIN = 3   # wol-update mulai versi ini bisa memperbarui dirinya


def vm_template_version():
    try:
        with open(VM_TEMPLATE, encoding="utf-8") as f:
            m = re.search(r"^WOL_UPDATE_VERSION=(\d+)$", f.read(), re.M)
        return int(m.group(1)) if m else 0
    except OSError:
        return 0


def load_vmstate():
    global VMSTATE
    try:
        with open(VM_STATE_PATH, encoding="utf-8") as f:
            VMSTATE = json.load(f)
    except (FileNotFoundError, ValueError):
        VMSTATE = {}


def save_vmstate():
    tmp = VM_STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(VMSTATE, f, ensure_ascii=False)
    os.replace(tmp, VM_STATE_PATH)


def ensure_ssh_key():
    if not os.path.exists(SSH_KEY):
        os.makedirs(SSH_DIR, mode=0o700, exist_ok=True)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "wol-panel", "-f", SSH_KEY], check=True)
    with open(SSH_KEY + ".pub", encoding="utf-8") as f:
        return f.read().strip()


def ssh_cmd(vm, action):
    return ["ssh", "-i", SSH_KEY, "-p", str(int(vm.get("port", 22))),
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={os.path.join(SSH_DIR, 'known_hosts')}",
            "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=30", "-o", "LogLevel=ERROR",
            f"{vm.get('user', 'root')}@{vm['host']}", action]


def ssh_error(text, rc):
    t = (text or "").strip().splitlines()
    last = t[-1] if t else ""
    if "Permission denied" in last:
        return "Kunci panel ditolak VM — jalankan perintah pasang di VM ini."
    if "Host key verification failed" in last or "REMOTE HOST IDENTIFICATION" in (text or ""):
        return "Kunci host VM berubah (VM dipasang ulang?). Hapus lalu tambahkan lagi VM ini di panel."
    if "timed out" in last or "No route" in last or "Connection refused" in last:
        return "VM tidak terjangkau lewat SSH (mati, IP salah, atau SSH belum aktif)."
    if last.startswith("error="):
        return last[6:]
    return last or f"SSH gagal (kode {rc})."


def parse_kv(text):
    d = {"pkgs": [], "commits": []}
    for line in (text or "").splitlines():
        k, sep, v = line.partition("=")
        if not sep:
            continue
        if k == "pkg":
            p = v.split("|")
            if len(p) >= 4:
                d["pkgs"].append({"name": p[0], "from": p[1], "to": p[2], "src": p[3], "sec": "-security" in p[3]})
        elif k == "commit":
            p = v.split("|", 2)
            if len(p) == 3:
                d["commits"].append({"hash": p[0], "time": int(p[1] or 0), "msg": p[2]})
        elif k == "app_head":
            p = v.split("|", 2)
            d["app_head"] = {"hash": p[0], "time": int(p[1] or 0) if len(p) > 1 and p[1].isdigit() else 0,
                             "msg": p[2] if len(p) > 2 else ""} if v else None
        else:
            d[k] = v
    return d


def vm_check(vm, user="otomatis"):
    try:
        r = subprocess.run(ssh_cmd(vm, "check"), capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        err, data = "Cek melebihi 5 menit.", None
    else:
        data = parse_kv(r.stdout)
        err = None if r.returncode == 0 and data.get("host") else ssh_error(r.stderr + r.stdout, r.returncode)
    with VM_LOCK:
        st = VMSTATE.setdefault(vm["id"], {})
        st["checked"] = int(time.time())
        st["error"] = err
        if data and not err:
            st["data"] = data
        save_vmstate()
    return err


def vm_job_running(vm_id):
    j = VM_JOBS.get(vm_id)
    return bool(j and j.get("end") is None)


def vm_log_path(vm_id):
    return os.path.join(VM_LOG_DIR, f"{vm_id}.log")


def run_vm_job(vm, action, user):
    """Jalankan aksi di VM di latar belakang; keluaran ditulis ke log agar bisa dipantau langsung."""
    os.makedirs(VM_LOG_DIR, exist_ok=True)
    job = {"action": action, "start": int(time.time()), "end": None, "rc": None, "by": user}
    VM_JOBS[vm["id"]] = job

    def work():
        path = vm_log_path(vm["id"])
        with open(path, "w", encoding="utf-8") as log:
            log.write(f"# {VM_ACTIONS.get(action, action)} di {vm['name']} oleh {user} — {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            log.flush()
            try:
                p = subprocess.Popen(ssh_cmd(vm, action), stdout=log, stderr=subprocess.STDOUT, text=True)
                rc = p.wait(timeout=3600)
            except subprocess.TimeoutExpired:
                p.kill()
                rc = -1
                log.write("\n[panel] Dihentikan: melebihi 60 menit.\n")
            except Exception as e:
                rc = -1
                log.write(f"\n[panel] Gagal menjalankan SSH: {e}\n")
            log.write(f"\n[panel] Selesai dengan kode {rc}.\n")
        job["rc"], job["end"] = rc, int(time.time())
        write_log(user, "vm-" + action + ("" if rc == 0 else "-gagal"), f"{vm['id']}:{vm['name']}", "-")
        with VM_LOCK:
            st = VMSTATE.setdefault(vm["id"], {})
            st["last_job"] = {k: job[k] for k in ("action", "start", "end", "rc", "by")}
            save_vmstate()
        if action != "reboot":
            vm_check(vm, user)
        elif rc == 0:
            wait_vm_back(vm)

    threading.Thread(target=work, daemon=True).start()


def wait_vm_back(vm):
    """Setelah reboot: tandai 'sedang restart', lalu cek berkala sampai VM bisa dijangkau lagi (maks. 10 menit)."""
    with VM_LOCK:
        VMSTATE.setdefault(vm["id"], {})["rebooting"] = int(time.time())
        save_vmstate()
    time.sleep(20)
    for _ in range(20):
        if vm_check(vm, "otomatis") is None:
            break
        time.sleep(30)
    with VM_LOCK:
        VMSTATE.setdefault(vm["id"], {}).pop("rebooting", None)
        save_vmstate()


def check_all_vms(only_due=True):
    hours = float(CFG.get("vm_check_hours", 6))
    for vm in list(CFG.get("vms", [])):
        last = (VMSTATE.get(vm["id"]) or {}).get("checked", 0)
        if only_due and (hours <= 0 or time.time() - last < hours * 3600):
            continue
        if vm_job_running(vm["id"]):
            continue
        try:
            vm_check(vm)
        except Exception as e:
            print("cek VM gagal", vm["id"], e, file=sys.stderr)


# ------------------------------------------------------- terminal web (dibatasi)
TERM_KEY = os.path.join(SSH_DIR, "terminal_ed25519")
TERM_LOG_DIR = os.path.join(BASE, "vmlogs", "terminal")
TERM_UNLOCK = {}      # hash token login -> kedaluwarsa (setelah ketik ulang password)
TERM_UNLOCK_TTL = 30 * 60
TERM_IDLE = 30 * 60
TERM_MAX_BUF = 1 << 20
TERMS = {}            # id sesi -> TermSession
TERMS_LOCK = threading.Lock()


def ensure_term_key():
    if not os.path.exists(TERM_KEY):
        os.makedirs(SSH_DIR, mode=0o700, exist_ok=True)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "wol-panel-terminal", "-f", TERM_KEY], check=True)
    with open(TERM_KEY + ".pub", encoding="utf-8") as f:
        return f.read().strip()


def tok_hash(tok):
    return hashlib.sha256(tok.encode()).hexdigest()


def term_unlocked(tok):
    exp = TERM_UNLOCK.get(tok_hash(tok), 0)
    if exp > time.time():
        TERM_UNLOCK[tok_hash(tok)] = time.time() + TERM_UNLOCK_TTL  # diperpanjang selama dipakai
        return True
    TERM_UNLOCK.pop(tok_hash(tok), None)
    return False


class TermSession:
    def __init__(self, vm, user, tok):
        self.id = secrets.token_urlsafe(16)
        self.vm, self.user, self.owner = vm, user, tok_hash(tok)
        self.buf = bytearray()
        self.base = 0                     # posisi byte pertama di buf
        self.cond = threading.Condition()
        self.alive = True
        self.rc = None
        self.started = self.last = time.time()
        os.makedirs(TERM_LOG_DIR, exist_ok=True)
        self.log_path = os.path.join(TERM_LOG_DIR, f"{vm['id']}-{time.strftime('%Y%m%d-%H%M%S')}-{user}.log")
        self.log = open(self.log_path, "ab")
        self.log.write(f"# Terminal {vm['name']} ({vm['host']}) dibuka oleh {user} — {time.strftime('%Y-%m-%d %H:%M:%S')}\n".encode())
        import pty
        self.master, slave = pty.openpty()
        self.resize(30, 100)
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "TERM": "xterm-256color", "LANG": "C.UTF-8", "HOME": BASE}

        def child_setup():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        cmd = ["ssh", "-tt", "-i", TERM_KEY, "-p", str(int(vm.get("port", 22))),
               "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
               "-o", f"UserKnownHostsFile={os.path.join(SSH_DIR, 'known_hosts')}", "-o", "ConnectTimeout=8",
               "-o", "ServerAliveInterval=30", "-o", "LogLevel=ERROR", f"{vm.get('user', 'root')}@{vm['host']}"]
        self.proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, env=env,
                                     preexec_fn=child_setup, close_fds=True)
        os.close(slave)
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        while True:
            try:
                data = os.read(self.master, 65536)
            except OSError:
                data = b""
            if not data:
                break
            self._append(data)
        self.rc = self.proc.wait()
        msg = "\r\n[panel] Sesi selesai." if self.rc in (0, None) else \
              f"\r\n[panel] Koneksi terputus (kode {self.rc}). Pastikan terminal sudah diizinkan di VM ini."
        self._append(msg.encode())
        with self.cond:
            self.alive = False
            self.cond.notify_all()
        try:
            self.log.write(f"\n# Ditutup — {time.strftime('%Y-%m-%d %H:%M:%S')}\n".encode())
            self.log.close()
        except Exception:
            pass
        try:
            os.close(self.master)
        except OSError:
            pass

    def _append(self, data):
        with self.cond:
            self.buf += data
            if len(self.buf) > TERM_MAX_BUF:
                cut = len(self.buf) - TERM_MAX_BUF
                del self.buf[:cut]
                self.base += cut
            self.cond.notify_all()
        try:
            self.log.write(data)
            self.log.flush()
        except Exception:
            pass

    def read(self, since, wait=20):
        end = time.time() + wait
        with self.cond:
            while self.alive and self.base + len(self.buf) <= since and time.time() < end:
                self.cond.wait(max(0.0, end - time.time()))
            start = max(since, self.base)
            data = bytes(self.buf[start - self.base:])
            return data, self.base + len(self.buf), self.alive

    def write(self, data):
        self.last = time.time()
        if self.alive:
            try:
                os.write(self.master, data)
            except OSError:
                pass

    def resize(self, rows, cols):
        try:
            fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", max(5, min(rows, 300)), max(20, min(cols, 500)), 0, 0))
        except OSError:
            pass

    def close(self):
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGHUP)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def term_reaper():
    while True:
        time.sleep(30)
        now = time.time()
        with TERMS_LOCK:
            items = list(TERMS.items())
        for sid, t in items:
            if t.alive and now - t.last > TERM_IDLE:
                t._append(b"\r\n[panel] Ditutup otomatis: tidak ada aktivitas 30 menit.")
                t.close()
            if not t.alive and now - t.last > 600:
                with TERMS_LOCK:
                    TERMS.pop(sid, None)


def vm_install_script(vm):
    with open(VM_TEMPLATE, encoding="utf-8") as f:
        helper = f.read()
    pub = ensure_ssh_key()
    term_pub = ensure_term_key() if vm.get("terminal") else ""
    panel_ip = local_ip_for(vm["host"])
    if "WOLEOF" in helper:
        raise ValueError("template vm-update.sh tidak valid")
    return f"""#!/bin/bash
# Pemasang akses update WOL Panel untuk VM "{vm['name']}". Jalankan sebagai root.
set -e
[ "$(id -u)" -eq 0 ] || {{ echo "Jalankan sebagai root: sudo -i lalu ulangi perintahnya."; exit 1; }}
PANEL_IP='{panel_ip}'
PUBKEY='{pub}'
TERM_PUBKEY='{term_pub}'

echo "==> Memasang /usr/local/sbin/wol-update"
cat > /usr/local/sbin/wol-update <<'WOLEOF'
{helper}
WOLEOF
chown root:root /usr/local/sbin/wol-update; chmod 755 /usr/local/sbin/wol-update

if [ ! -f /etc/wol-update.conf ] || ! grep -q '^APP_DIR="/' /etc/wol-update.conf; then
  APP=""
  for f in /var/www/*/deploy/update.sh /var/www/*/*/deploy/update.sh /root/wol-panel/deploy/update.sh; do
    [ -f "$f" ] && {{ APP="$(dirname "$(dirname "$f")")"; break; }}
  done
  echo "APP_DIR=\\"$APP\\"" > /etc/wol-update.conf
fi
. /etc/wol-update.conf
echo "    Folder aplikasi: ${{APP_DIR:-(tidak ditemukan — hanya update OS)}}"

echo "==> Memasang kunci SSH panel (hanya untuk wol-update, hanya dari $PANEL_IP)"
command -v sshd >/dev/null 2>&1 || {{ apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server >/dev/null; }}
install -d -m 700 /root/.ssh; touch /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys
grep -v -e 'wol-panel-update$' -e 'wol-panel-terminal$' /root/.ssh/authorized_keys > /root/.ssh/authorized_keys.tmp || true
echo "restrict,from=\\"$PANEL_IP\\",command=\\"/usr/local/sbin/wol-update\\" $PUBKEY wol-panel-update" >> /root/.ssh/authorized_keys.tmp
if [ -n "$TERM_PUBKEY" ]; then
  # terminal web: shell root, hanya dari IP panel
  echo "from=\\"$PANEL_IP\\",no-agent-forwarding,no-port-forwarding,no-X11-forwarding $TERM_PUBKEY wol-panel-terminal" >> /root/.ssh/authorized_keys.tmp
  echo "==> Terminal web DIIZINKAN untuk VM ini (hanya dari $PANEL_IP)"
else
  echo "==> Terminal web tidak diizinkan untuk VM ini"
fi
mv /root/.ssh/authorized_keys.tmp /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys

# Izin login root khusus IP panel bila sshd menolak root secara umum
sed -i '/^# >>> WOL Panel/,/^# <<< WOL Panel/d; /^# WOL Panel: root hanya/,+2d' /etc/ssh/sshd_config
if [ "$(sshd -T -C user=root,host=x,addr=203.0.113.1 2>/dev/null | awk '/^permitrootlogin/{{print $2}}')" = "no" ]; then
  MODE=forced-commands-only; [ -n "$TERM_PUBKEY" ] && MODE=prohibit-password
  printf '\\n# >>> WOL Panel (dikelola otomatis)\\nMatch Address %s\\n    PermitRootLogin %s\\n# <<< WOL Panel\\n' "$PANEL_IP" "$MODE" >> /etc/ssh/sshd_config
  echo "    sshd_config: root dari $PANEL_IP diizinkan ($MODE)"
fi
sshd -t || {{ echo "Konfigurasi sshd tidak valid, dibatalkan."; exit 1; }}
systemctl enable ssh >/dev/null 2>&1 || true
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true

/usr/local/sbin/wol-update status >/dev/null && echo "Berhasil. Kembali ke WOL Panel lalu klik Cek pada VM ini."
"""


def new_vm_token(vm_id):
    now = time.time()
    for t, (_, exp) in list(VM_TOKENS.items()):
        if exp < now:
            VM_TOKENS.pop(t, None)
    tok = secrets.token_urlsafe(24)
    VM_TOKENS[tok] = (vm_id, now + AGENT_TOKEN_TTL)
    return tok


def new_agent_token(dev_id):
    now = time.time()
    for t, (_, exp) in list(AGENT_TOKENS.items()):
        if exp < now:
            AGENT_TOKENS.pop(t, None)
    tok = secrets.token_urlsafe(24)
    AGENT_TOKENS[tok] = (dev_id, now + AGENT_TOKEN_TTL)
    return tok


def agent_script(dev):
    with open(AGENT_TEMPLATE, encoding="utf-8") as f:
        tpl = f.read()
    return (tpl.replace("__SECRET__", dev["agent_secret"])
               .replace("__PORT__", str(int(dev.get("agent_port", AGENT_PORT))))
               .replace("__PANEL_IP__", local_ip_for(dev["ip"])))


def all_status():
    devs = list(CFG.get("devices", []))
    if not devs:
        return {}
    with ThreadPoolExecutor(max_workers=min(16, len(devs))) as ex:
        res = list(ex.map(is_online, devs))
    return {d["id"]: r for d, r in zip(devs, res)}


def write_log(user, action, target, ip):
    clean = lambda v: re.sub(r"[\t\r\n]+", " ", str(v))
    line = "\t".join([time.strftime('%Y-%m-%d %H:%M:%S'), clean(user), clean(action), clean(target), clean(ip)]) + "\n"
    with LOG_LOCK, open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line)


def read_log(n=15):
    try:
        with open(LOG_PATH, encoding="utf-8") as f:
            lines = f.readlines()[-n:]
    except FileNotFoundError:
        return []
    return [l.rstrip("\n").split("\t") for l in reversed(lines)]


# ------------------------------------------------------------- validasi
def build_device(form, others):
    """Membuat data perangkat dari isian form. Mengembalikan (device, pesan_error)."""
    name = form.get("name", "").strip()
    if not name or len(name) > 60:
        return None, "Nama komputer wajib diisi (maks. 60 karakter)."
    did = form.get("id", "").strip().lower() or slugify(name)
    if not ID_RE.match(did):
        return None, "ID hanya boleh huruf kecil, angka, dan tanda minus (maks. 32 karakter)."
    if any(d["id"] == did for d in others):
        return None, f"ID '{did}' sudah dipakai komputer lain."
    try:
        mac = normalize_mac(form.get("mac", ""))
    except ValueError:
        return None, "MAC address tidak valid. Contoh: 3C:7C:3F:12:34:56"
    ip = form.get("ip", "").strip()
    if ip:
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            return None, "IP komputer tidak valid."
    bc = form.get("broadcast", "").strip()
    if not bc:
        bc = str(ipaddress.ip_network(f"{ip}/24", strict=False).broadcast_address) if ip else "255.255.255.255"
    try:
        ipaddress.IPv4Address(bc)
    except ValueError:
        return None, "Alamat broadcast tidak valid."
    try:
        port = int(form.get("port") or 9)
        checks = [int(p) for p in re.split(r"[,\s]+", form.get("check_ports", "")) if p]
        if not 1 <= port <= 65535 or any(not 1 <= p <= 65535 for p in checks):
            raise ValueError
    except ValueError:
        return None, "Nomor port harus angka 1–65535."
    remote = form.get("remote_url", "").strip() or DEFAULT_REMOTE
    if not re.match(r"^https?://[^\s\"'<>]+$", remote) or len(remote) > 300:
        return None, "Link remote harus diawali http:// atau https://"
    return {"id": did, "name": name, "mac": mac, "ip": ip, "broadcast": bc,
            "port": port, "check_ports": checks, "remote_url": remote}, None


# ------------------------------------------------------------------ sesi
def _sign(data):
    return hmac.new(CFG["secret"].encode(), data.encode(), hashlib.sha256).hexdigest()


def make_session(user):
    exp = int(time.time() + int(CFG.get("session_hours", 12)) * 3600)
    sv = CFG["users"][user].get("sv", 0)
    raw = f"{user}|{exp}|{sv}|{secrets.token_hex(8)}"
    return base64.urlsafe_b64encode(f"{raw}|{_sign(raw)}".encode()).decode()


def verify_session(token):
    try:
        user, exp, sv, nonce, sig = base64.urlsafe_b64decode(token.encode()).decode().split("|")
        raw = f"{user}|{exp}|{sv}|{nonce}"
        u = CFG["users"].get(user)
        if u and hmac.compare_digest(sig, _sign(raw)) and int(exp) > time.time() and int(sv) == u.get("sv", 0):
            return user
    except Exception:
        pass
    return None


def csrf_for(token):
    return _sign("csrf|" + token)[:32]


# ------------------------------------------------------------------ HTML
E = html.escape

CSS = """
:root{color-scheme:light dark;
--bg:#f3f5f7;--card:#fff;--field:#fff;--fg:#17202a;--mut:#56616d;--faint:#8a95a1;--line:#e1e6eb;--line2:#cfd6dd;
--acc:#1f6feb;--acc-soft:#e9f1fe;--ok:#1a7f37;--ok-soft:#e7f5ea;--off:#7d8791;--off-soft:#eef1f4;
--warn:#8a5d00;--warn-soft:#fff3d1;--err:#c62430;--err-soft:#fdecee;--ring:rgba(31,111,235,.35);--shadow:0 1px 2px rgba(16,24,40,.06)}
@media (prefers-color-scheme:dark){:root{
--bg:#0e1319;--card:#161d25;--field:#10161d;--fg:#e6edf3;--mut:#a0acb8;--faint:#6f7b87;--line:#28313b;--line2:#36404b;
--acc:#4493f8;--acc-soft:#132438;--ok:#3fb950;--ok-soft:#11261a;--off:#7d8791;--off-soft:#1c242d;
--warn:#d9a227;--warn-soft:#2a2210;--err:#f85149;--err-soft:#2c1517;--ring:rgba(68,147,248,.45);--shadow:none}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
a{color:var(--acc)}
.wrap{max-width:760px;margin:0 auto;padding:16px 16px 48px}
.mono{font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;font-size:.92em}
.mut{color:var(--mut)}.small{font-size:13px}
h1,h2,h3{margin:0;line-height:1.3}h2{font-size:16px}h3{font-size:15px}
svg.i{width:18px;height:18px;flex:none;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}

/* header */
.top{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:6px 0 16px}
.brand{display:flex;align-items:center;gap:10px;text-decoration:none;color:var(--fg)}
.logo{width:34px;height:34px;border-radius:10px;background:var(--acc);color:#fff;display:grid;place-items:center}
.brand b{font-size:17px}.brand small{display:block;color:var(--mut);font-size:12px;font-weight:400}
.nav{display:flex;gap:4px;align-items:center;flex-wrap:wrap}
.nav a{color:var(--mut);text-decoration:none;padding:8px 12px;border-radius:8px;font-weight:500}
.nav a:hover{color:var(--fg);background:var(--off-soft)}
.nav a[aria-current=page]{color:var(--fg);background:var(--card);box-shadow:inset 0 0 0 1px var(--line)}
.nav form{margin:0}
@media (max-width:640px){.top{flex-wrap:nowrap;flex-direction:column;align-items:stretch;gap:4px;padding:0 0 8px}
.nav{flex-wrap:nowrap;overflow-x:auto;scrollbar-width:none;margin:0 -16px;padding:0 16px}.nav::-webkit-scrollbar{display:none}
.nav a,.nav form{flex:none}}
@media (pointer:coarse){.nav a,.tabs a{min-height:44px;display:flex;align-items:center;justify-content:center}
input,select{height:44px}
details.more summary{min-height:44px}}

/* card & layout */
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;margin-bottom:12px;box-shadow:var(--shadow)}
.card>h2{margin-bottom:12px}
.sec-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:22px 0 10px}
.sec-head:first-child{margin-top:4px}
.sec-head h2{font-size:15px;color:var(--mut);font-weight:600}

/* buttons */
.btn{font:inherit;font-weight:600;font-size:14px;display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:40px;
padding:0 16px;border-radius:9px;border:1px solid var(--line2);background:var(--card);color:var(--fg);cursor:pointer;text-decoration:none;white-space:nowrap}
.btn:hover{background:var(--off-soft)}
.btn.primary{background:var(--acc);border-color:var(--acc);color:#fff}.btn.primary:hover{filter:brightness(1.08)}
.btn.danger{color:var(--err);border-color:var(--line2)}.btn.danger:hover{background:var(--err-soft);border-color:var(--err)}
.btn.danger-solid{background:var(--err);border-color:var(--err);color:#fff}
.btn.quiet{border-color:transparent;background:transparent;color:var(--mut);padding:0 10px}
.btn.quiet:hover{color:var(--fg);background:var(--off-soft)}
.btn.quiet.danger{color:var(--err)}.btn.quiet.danger:hover{background:var(--err-soft)}
.btn.sm{min-height:34px;padding:0 12px;font-size:13px}
.btn:disabled,.btn[aria-disabled=true]{opacity:.55;cursor:default;filter:none}
.btn:focus-visible,.nav a:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible{outline:none;box-shadow:0 0 0 3px var(--ring)}
@media (pointer:coarse){.btn{min-height:44px}.btn.sm{min-height:40px}}
.spin{width:14px;height:14px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:sp .8s linear infinite}
@keyframes sp{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.spin,.pill.wait .dot{animation:none}}
.acts{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.acts form{margin:0}

/* status pill */
.pill{display:inline-flex;align-items:center;gap:7px;font-size:13px;font-weight:600;padding:3px 10px 3px 8px;border-radius:99px;
background:var(--off-soft);color:var(--mut);white-space:nowrap}
.pill .dot{width:8px;height:8px;border-radius:50%;background:var(--off)}
.pill.on{background:var(--ok-soft);color:var(--ok)}.pill.on .dot{background:var(--ok)}
.pill.wait{background:var(--warn-soft);color:var(--warn)}.pill.wait .dot{background:var(--warn);animation:pulse 1.2s ease-in-out infinite}
.pill.bad{background:var(--err-soft);color:var(--err)}.pill.bad .dot{background:var(--err)}
@keyframes pulse{50%{opacity:.3}}
.tag{display:inline-block;font-size:12px;font-weight:600;padding:1px 8px;border-radius:99px;background:var(--off-soft);color:var(--mut);vertical-align:2px}
.tag.ok{background:var(--ok-soft);color:var(--ok)}.tag.acc{background:var(--acc-soft);color:var(--acc)}
.tag.warn{background:var(--warn-soft);color:var(--warn)}.tag.bad{background:var(--err-soft);color:var(--err)}
a.tag{text-decoration:none}
.search{margin:0 0 12px}.search input{margin:0}
.group+.group{margin-top:16px;padding-top:14px;border-top:1px solid var(--line)}
.group-head{display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:baseline;margin-bottom:6px}
pre.log{background:#0d1117;color:#d1d9e0;font:12px/1.5 ui-monospace,Consolas,monospace;padding:12px;border-radius:9px;
max-height:340px;overflow:auto;white-space:pre-wrap;word-break:break-word;margin:0}
.joblog{margin:0}
details.menu{position:relative}details.menu summary{list-style:none}details.menu summary::-webkit-details-marker{display:none}
.menu-pop{position:absolute;right:0;top:calc(100% + 4px);z-index:5;min-width:190px;background:var(--card);border:1px solid var(--line);
border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.12);padding:6px;display:grid;gap:2px}
.menu-pop form{margin:0}.menu-pop .btn{width:100%;justify-content:flex-start}
@media (max-width:520px){.vm .dev-acts{display:grid;grid-template-columns:1fr 1fr;gap:8px}.vm .dev-acts>*{flex:none}}
.inline{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end}.inline label{margin:0;flex:1 1 200px}

/* device card */
.dev{display:grid;gap:14px}
.dev-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
.dev-head h2{font-size:17px}
.meta{color:var(--mut);font-size:13px;display:flex;gap:4px 12px;flex-wrap:wrap;margin-top:2px}
.dev-acts{display:flex;gap:8px;flex-wrap:wrap;align-items:center;border-top:1px solid var(--line);padding-top:14px}
.dev-acts form{margin:0}.dev-acts .push{margin-left:auto}
.dev .a-stop{display:none}
.dev[data-state=on] .a-wake{display:none}
.dev[data-state=on] .a-stop{display:block}
.dev[data-state=on] .a-remote{background:var(--acc);border-color:var(--acc);color:#fff}
.dev[data-state=stop] .a-stop{display:none}
.dev-note{font-size:13px;color:var(--mut);margin:-4px 0 0}
.dev-note:empty{display:none}
@media (max-width:520px){.dev-acts>*{flex:1 1 100%}.dev-acts .btn{width:100%}.dev-acts .push{margin:6px 0 0}}

/* list rows (settings, users, log) */
.list{display:grid}
.row{display:flex;align-items:center;justify-content:space-between;gap:10px 16px;flex-wrap:wrap;padding:12px 0;border-top:1px solid var(--line)}
.row:first-child{border-top:0;padding-top:0}.row:last-child{padding-bottom:0}
.row-main{min-width:0}.row-main b{font-weight:600}
.log .row{padding:9px 0;align-items:baseline;flex-wrap:nowrap}.log .row-main{flex:1}
.log time{color:var(--mut);font-size:13px;white-space:nowrap}

/* flash */
.flash{display:flex;gap:10px;align-items:flex-start;padding:12px 14px;border-radius:12px;margin-bottom:14px;
background:var(--ok-soft);color:var(--fg);border:1px solid color-mix(in srgb,var(--ok) 35%,transparent)}
.flash.err{background:var(--err-soft);border-color:color-mix(in srgb,var(--err) 35%,transparent)}
.flash.info{background:var(--acc-soft);border-color:color-mix(in srgb,var(--acc) 30%,transparent)}
.flash .i{margin-top:2px}.flash.err .i{color:var(--err)}.flash .i{color:var(--ok)}.flash.info .i{color:var(--acc)}
.flash div{flex:1}.flash ul{margin:6px 0 0;padding-left:18px}.flash li{margin:2px 0}
.flash .x{background:none;border:0;color:var(--mut);cursor:pointer;font-size:20px;line-height:1;padding:0 4px}

/* tabs */
.tabs{display:flex;gap:4px;background:var(--off-soft);padding:4px;border-radius:11px;margin-bottom:16px;overflow-x:auto}
.tabs a{flex:1;text-align:center;padding:8px 12px;border-radius:8px;text-decoration:none;color:var(--mut);font-weight:600;font-size:14px;white-space:nowrap}
.tabs a[aria-current=page]{background:var(--card);color:var(--fg);box-shadow:var(--shadow),inset 0 0 0 1px var(--line)}

/* forms */
label{display:block;font-size:13px;font-weight:600;color:var(--fg);margin-bottom:14px}
label .hint{display:block;font-weight:400;color:var(--mut);margin-top:4px}
input,select{font:inherit;font-weight:400;width:100%;height:40px;padding:0 12px;border-radius:9px;border:1px solid var(--line2);background:var(--field);color:var(--fg);margin-top:6px}
input::placeholder{color:var(--faint)}
input[readonly]{background:var(--off-soft)}
.check{display:flex;gap:10px;align-items:flex-start;font-weight:600}
.check input{width:18px;height:18px;margin:2px 0 0;flex:none;accent-color:var(--acc)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:0 14px}@media(max-width:560px){.grid{grid-template-columns:1fr}}
details.more{border-top:1px solid var(--line);margin:4px 0 16px;padding-top:12px}
details.more summary{cursor:pointer;font-weight:600;font-size:14px;color:var(--mut);list-style:none;display:flex;align-items:center;gap:6px}
details.more summary::-webkit-details-marker{display:none}
details.more summary::before{content:"▸";transition:transform .15s}
details.more[open] summary::before{transform:rotate(90deg)}
details.more[open] summary{margin-bottom:14px}
.cmd{display:flex;gap:8px}.cmd input{margin:0;font-family:ui-monospace,Consolas,monospace;font-size:13px}
ol.steps{margin:0 0 14px;padding-left:20px}ol.steps li{margin:4px 0}
.empty{text-align:center;padding:28px 16px;color:var(--mut)}
.empty .i{width:28px;height:28px;color:var(--faint)}
.foot{color:var(--mut);font-size:13px;margin-top:6px}

/* dialog */
dialog{border:1px solid var(--line);border-radius:14px;padding:20px;max-width:400px;width:calc(100% - 32px);background:var(--card);color:var(--fg);box-shadow:0 20px 50px rgba(0,0,0,.25)}
dialog::backdrop{background:rgba(10,15,20,.5)}
dialog h3{margin-bottom:6px}dialog p{margin:0 0 18px;color:var(--mut)}
dialog .acts{justify-content:flex-end}

/* login */
.login{max-width:380px;margin:10vh auto 0}
.login .logo{width:44px;height:44px;border-radius:12px;margin-bottom:14px}
.login h1{font-size:20px;margin-bottom:4px}.login p{margin:0 0 18px}
"""

ICONS = {
    "power": '<path d="M12 3v9"/><path d="M18.4 6.6a9 9 0 1 1-12.8 0"/>',
    "ext": '<path d="M14 4h6v6"/><path d="M20 4l-9 9"/><path d="M19 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h5"/>',
    "check": '<path d="M20 6 9 17l-5-5"/>',
    "alert": '<circle cx="12" cy="12" r="9"/><path d="M12 8v5"/><path d="M12 16.5v.01"/>',
    "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><path d="M12 7.5v.01"/>',
    "plus": '<path d="M12 5v14"/><path d="M5 12h14"/>',
    "monitor": '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8"/><path d="M12 16v4"/>',
    "copy": '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a1 1 0 0 1 1-1h10"/>',
}


def icon(name):
    return f'<svg class="i" viewBox="0 0 24 24" aria-hidden="true">{ICONS[name]}</svg>'


JS_BASE = """
(function(){
  // bersihkan pesan dari URL agar tidak muncul lagi saat halaman dimuat ulang
  var u=new URL(location.href),keep=['tab','edit','agent','tok','reset','new'],dirty=false;
  ['msg','err','waking','stopping'].forEach(function(k){if(u.searchParams.has(k)){u.searchParams.delete(k);dirty=true}});
  for(var k of Array.from(u.searchParams.keys())){if(k.indexOf('f_')===0){u.searchParams.delete(k);dirty=true}}
  if(dirty)history.replaceState(null,'',u.pathname+(u.search||'')+u.hash);
  document.querySelectorAll('.flash .x').forEach(function(b){b.onclick=function(){b.closest('.flash').remove()}});
  var ok=document.querySelector('.flash:not(.err):not(.info)');
  if(ok&&!ok.querySelector('ul'))setTimeout(function(){ok.remove()},6000);

  var dlg=document.getElementById('dlg');
  document.addEventListener('submit',function(e){
    var f=e.target;
    if(f.dataset.confirm&&f.dataset.confirmed!=='1'){
      e.preventDefault();
      if(!dlg||!dlg.showModal){ if(confirm(f.dataset.confirm)){f.dataset.confirmed='1';f.submit()} return; }
      dlg.querySelector('h3').textContent=f.dataset.title||'Yakin?';
      dlg.querySelector('p').textContent=f.dataset.confirm;
      var okb=dlg.querySelector('[value=ok]');okb.textContent=f.dataset.ok||'Ya';
      dlg.onclose=function(){ if(dlg.returnValue==='ok'){f.dataset.confirmed='1';
        if(f.requestSubmit)f.requestSubmit();else f.submit();} };
      dlg.returnValue='';dlg.showModal();okb.focus();return;
    }
    var b=f.querySelector('button[data-busy]');
    if(b)setTimeout(function(){b.disabled=true;b.innerHTML='<span class="spin"></span>'+b.dataset.busy},0);
  });

  document.querySelectorAll('[data-copy]').forEach(function(b){
    b.onclick=function(){var i=document.getElementById(b.dataset.copy);i.select();
      var done=function(){var t=b.innerHTML;b.textContent='Tersalin';setTimeout(function(){b.innerHTML=t},1500)};
      if(navigator.clipboard&&window.isSecureContext)navigator.clipboard.writeText(i.value).then(done);
      else{try{document.execCommand('copy');done()}catch(e){}}};
  });
})();
"""

JS_STATUS = """
(function(){
  var T={on:'Menyala',off:'Mati',unknown:'Status tidak dicek',checking:'Mengecek…',
         wake:'Sedang dihidupkan…',stop:'Sedang dimatikan…',slow:'Belum merespons'};
  var C={on:'on',off:'',unknown:'',checking:'',wake:'wait',stop:'wait',slow:'bad'};
  var N={wake:'Biasanya butuh 30–90 detik sampai Windows siap.',stop:'Windows sedang menutup aplikasi lalu mati.',
         slow:'Sudah lebih dari 3 menit. Cek kabel LAN dan pengaturan Wake-on-LAN di BIOS komputer ini.',
         unknown:'Isi IP komputer di Pengaturan agar statusnya bisa dicek.'};
  var t0=Date.now();
  function apply(card,s){
    var p=card.dataset.pending,st;
    if(p==='wake'){ if(s===true){card.dataset.pending='';st='on'} else st=(Date.now()-t0>180000)?'slow':'wake'; }
    else if(p==='stop'){ if(s===false){card.dataset.pending='';st='off'} else st='stop'; }
    else st= s===true?'on':s===false?'off':'unknown';
    card.dataset.state=st==='slow'?'off':st;
    var pill=card.querySelector('.pill');pill.className='pill '+C[st];pill.lastChild.textContent=T[st];
    card.querySelector('.dev-note').textContent=N[st]||'';
    var w=card.querySelector('.a-wake button');
    if(w){var busy=st==='wake'||st==='stop';w.disabled=busy;
      w.innerHTML=st==='wake'?'<span class="spin"></span>Menyalakan…':w.dataset.label;}
  }
  document.querySelectorAll('.dev').forEach(function(c){
    var w=c.querySelector('.a-wake button');if(w)w.dataset.label=w.innerHTML;
    if(c.dataset.pending)apply(c,null);
  });
  async function refresh(){
    try{
      var r=await fetch('/api/status',{cache:'no-store'});
      if(r.status===401){location='/login';return}
      var s=await r.json();
      for(var id in s){var c=document.getElementById('dev-'+id);if(c)apply(c,s[id]);}
    }catch(e){}
  }
  refresh();setInterval(refresh,5000);
})();
"""

LOG_LABELS = {
    "login": "Masuk ke panel", "nyalakan": "Menyalakan", "matikan": "Mematikan",
    "simpan-perangkat": "Menyimpan data komputer", "hapus-perangkat": "Menghapus komputer",
    "simpan-pengguna": "Menyimpan pengguna", "hapus-pengguna": "Menghapus pengguna",
    "ganti-password": "Mengganti password", "pengaturan-umum": "Mengubah pengaturan umum",
    "token-agen": "Membuat perintah pasang agen", "unduh-agen": "Pemasang agen diunduh",
    "lepas-agen": "Melepas agen",
    "pindai": "Memindai aplikasi", "uninstall": "Uninstall", "uninstall-gagal": "Uninstall gagal",
    "hapus-otomatis": "Hapus otomatis", "hapus-otomatis-gagal": "Hapus otomatis gagal",
    "aturan-aplikasi": "Mengubah aturan aplikasi", "perbarui-agen": "Memperbarui agen",
    "terminal": "Membuka terminal", "terminal-izin": "Mengizinkan terminal", "terminal-cabut": "Mencabut izin terminal",
    "terminal-gagal": "Password terminal salah", "terminal-buka-kunci": "Membuka kunci terminal",
    "tambah-vm": "Menambah VM", "ubah-vm": "Mengubah data VM", "hapus-vm": "Menghapus VM", "unduh-vm": "Skrip pasang VM diunduh",
    "vm-os-upgrade": "Update OS", "vm-os-upgrade-gagal": "Update OS gagal", "vm-app-update": "Update aplikasi",
    "vm-app-update-gagal": "Update aplikasi gagal", "vm-reboot": "Reboot", "vm-reboot-gagal": "Reboot gagal",
}


def page(title, body, script=""):
    return f"""<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">
<title>{E(title)}</title><style>{CSS}</style></head><body><div class="wrap">{body}</div>
<dialog id="dlg" aria-labelledby="dlg-t"><form method="dialog"><h3 id="dlg-t">Yakin?</h3><p></p>
<div class="acts"><button class="btn" value="cancel">Batal</button><button class="btn danger-solid" value="ok">Ya</button></div></form></dialog>
<script>{JS_BASE}{script}</script></body></html>"""


def flash(q):
    msg = q.get("msg", [""])[0]
    if not msg:
        return ""
    err = bool(q.get("err"))
    parts = msg.split(" · ")
    if len(parts) > 1:  # hasil Tes: judul + daftar
        head, *items = parts
        if " — " in head:
            head, first = head.split(" — ", 1)
            items.insert(0, first)
        body = f"<b>{E(head)}</b><ul>{''.join(f'<li>{E(i)}</li>' for i in items)}</ul>"
        kind = "info"
    else:
        body = E(msg)
        kind = "err" if err else ""
    role = "alert" if err else "status"
    ic = "alert" if err else "info" if kind == "info" else "check"
    return (f'<div class="flash {kind}" role="{role}">{icon(ic)}<div>{body}</div>'
            f'<button class="x" type="button" aria-label="Tutup">×</button></div>')


def shell(user, csrf, active, content, q, script=""):
    links = [("/", "Beranda")]
    if is_admin(user):
        links.append(("/apps", "Aplikasi"))
        links.append(("/servers", "Server"))
        if any(v.get("terminal") for v in CFG.get("vms", [])):
            links.append(("/terminal", "Terminal"))
        links.append(("/settings", "Pengaturan"))
    links.append(("/account", "Akun"))
    nav = "".join(f'<a href="{h}"{" aria-current=page" if h == active else ""}>{t}</a>' for h, t in links)
    return page("WOL Panel", f"""<header class="top">
<a class="brand" href="/"><span class="logo">{icon('power')}</span><span><b>WOL Panel</b>
<small>{E(user)} · {'admin' if is_admin(user) else 'pengguna'}</small></span></a>
<nav class="nav" aria-label="Menu">{nav}<form method="post" action="/logout">{hidden(csrf)}
<button class="btn quiet sm">Keluar</button></form></nav></header>
<main>{flash(q)}{content}</main>""", script)


def hidden(csrf, **kw):
    return f'<input type="hidden" name="csrf" value="{csrf}">' + "".join(
        f'<input type="hidden" name="{k}" value="{E(str(v))}">' for k, v in kw.items())


def confirm(text, ok="Ya", title="Yakin?"):
    return f'data-confirm="{E(text)}" data-ok="{E(ok)}" data-title="{E(title)}"'


def del_form(action, csrf, text, title="Hapus?", **fields):
    return (f'<form method="post" action="{action}" {confirm(text, "Hapus", title)}>'
            f'{hidden(csrf, **fields)}<button class="btn quiet danger sm">Hapus</button></form>')


def login_page(err=""):
    e = (f'<div class="flash err" role="alert">{icon("alert")}<div>{E(err)}</div></div>') if err else ""
    return page("Masuk – WOL Panel", f"""<main class="login"><div class="card" style="padding:24px">
<span class="logo">{icon('power')}</span><h1>WOL Panel</h1>
<p class="mut">Masuk untuk menyalakan atau mematikan komputer.</p>{e}
<form method="post" action="/login"><label>Nama pengguna<input name="u" autocomplete="username" autocapitalize="none" required autofocus></label>
<label>Password<input name="p" type="password" autocomplete="current-password" required></label>
<button class="btn primary" style="width:100%" data-busy="Memeriksa…">Masuk</button></form></div></main>""")


def fmt_time(ts):
    try:
        d, t = ts.split(" ")
    except ValueError:
        return ts
    today = time.strftime("%Y-%m-%d")
    yest = time.strftime("%Y-%m-%d", time.localtime(time.time() - 86400))
    if d == today:
        return t[:5]
    if d == yest:
        return "Kemarin " + t[:5]
    y, m, dd = d.split("-")
    return f"{int(dd)}/{int(m)} {t[:5]}"


def log_list(n=8):
    names = {d["id"]: d["name"] for d in CFG.get("devices", [])}
    rows = []
    for r in read_log(n * 10):
        if len(rows) >= n:
            break
        if len(r) < 5:
            continue
        ts, who, act, target, ip = r[:5]
        if act == "login":  # tetap tercatat di wol.log, tapi menutupi kejadian penting di Beranda
            continue
        label = LOG_LABELS.get(act, act)
        if (act.startswith("vm-") or act.startswith("terminal")) and ":" in target:
            label += " " + target.split(":", 1)[1]
        elif act.startswith(("uninstall", "hapus-otomatis", "perbarui-agen")) and ":" in target:
            did, info = target.split(":", 1)
            label += f" di {names.get(did, did)} — {info}"
        elif act in ("pindai", "aturan-aplikasi"):
            label += f" {names.get(target, target)}" if target not in ("-", "", "semua") else (" semua komputer" if target == "semua" else "")
        elif target not in ("-", "") and act not in ("simpan-pengguna", "hapus-pengguna", "ganti-password"):
            label += f" {names.get(target, target)}"
        elif act in ("simpan-pengguna", "hapus-pengguna"):
            label += f" {target}"
        who = "Sistem" if who in ("-", "cli") else who
        rows.append(f'<div class="row"><div class="row-main"><b>{E(who)}</b> <span class="mut">{E(label)}</span>'
                    + (f'<div class="mut small mono">{E(ip)}</div>' if ip not in ("-", "") else "")
                    + f'</div><time>{E(fmt_time(ts))}</time></div>')
    return "".join(rows)


def home_page(user, csrf, q):
    waking, stopping = q.get("waking", [""])[0], q.get("stopping", [""])[0]
    cards = []
    for d in CFG.get("devices", []):
        did = E(d["id"])
        pending = "wake" if d["id"] == waking else "stop" if d["id"] == stopping else ""
        stop = ""
        if d.get("agent_secret"):
            stop = (f'<form class="a-stop push" method="post" action="/shutdown" '
                    f'{confirm(d["name"] + " akan mati 10 detik setelah ini. Pekerjaan yang belum disimpan di komputer itu akan hilang.", "Matikan", "Matikan " + d["name"] + "?")}>'
                    f'{hidden(csrf, id=d["id"])}<button class="btn danger" data-busy="Mengirim…">{icon("power")}Matikan</button></form>')
        warn = ""
        if is_admin(user):
            nf = len(flagged(d["id"]))
            if nf:
                warn = f'<div style="margin-top:6px"><a class="tag warn" href="/apps?dev={quote(d["id"])}">{nf} aplikasi cocok aturan</a></div>'
        edit = (f'<a class="btn quiet sm" href="/settings?edit={quote(d["id"])}#form-dev">Ubah</a>' if is_admin(user) else "")
        cards.append(f"""<article class="card dev" id="dev-{did}" data-state="checking" data-pending="{pending}">
<div class="dev-head"><div><h2>{E(d['name'])}</h2>
<div class="meta"><span>{E(d.get('ip') or 'IP belum diisi')}</span><span class="mono">{E(d['mac'])}</span></div>{warn}</div>
<span class="pill"><span class="dot"></span><span>Mengecek…</span></span></div>
<p class="dev-note" aria-live="polite"></p>
<div class="dev-acts">
<form class="a-wake" method="post" action="/wake">{hidden(csrf, id=d['id'])}<button class="btn primary" data-busy="Mengirim…">{icon('power')}Hidupkan</button></form>
<a class="btn a-remote" href="{E(d.get('remote_url') or DEFAULT_REMOTE)}" target="_blank" rel="noopener noreferrer">Buka Remote {icon('ext')}</a>
{stop}{edit}</div></article>""")
    if not cards:
        tip = ('<a class="btn primary" href="/settings?new=1#form-dev">' + icon("plus") + 'Tambah komputer</a>') if is_admin(user) \
            else '<p class="small">Hubungi admin untuk menambahkan komputer.</p>'
        cards.append(f'<div class="card empty">{icon("monitor")}<h3 style="margin:8px 0 4px">Belum ada komputer</h3>'
                     f'<p class="small" style="margin:0 0 14px">Tambahkan komputer yang ingin dinyalakan lewat panel ini.</p>{tip}</div>')
    attention = ""
    if is_admin(user):
        fl = failures()
        if fl:
            rows = []
            for d, aid, f in fl[:10]:
                a = next((x for x in (SCANS.get(d["id"]) or {}).get("apps", []) if x.get("id") == aid), {"id": aid, "name": f["name"]})
                t = fmt_time(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(f["time"])))
                who = "otomatis" if f.get("by") == "otomatis" else f"oleh {f.get('by')}"
                dismiss = (f'<form method="post" action="/apps/dismiss">{hidden(csrf, dev=d["id"], app=aid)}'
                           f'<button class="btn quiet sm" title="Sembunyikan dan jangan hapus otomatis lagi">Abaikan</button></form>')
                rows.append(f'<div class="row"><div class="row-main"><b>{E(f["name"])}</b> <span class="mut">di {E(d["name"])}</span>'
                            f'<div class="small" style="color:var(--err)">{E(f["msg"])}</div>'
                            f'<div class="mut small">Gagal {who} · {E(t)}</div></div>'
                            f'<div class="acts">{dismiss}{uninstall_form(csrf, d, a, back="home", label="Coba lagi")}</div></div>')
            more = f'<p class="foot" style="margin-top:10px">dan {len(fl) - 10} lainnya di menu Aplikasi.</p>' if len(fl) > 10 else ""
            attention = (f'<div class="sec-head"><h2>Perlu ditangani manual <span class="tag bad">{len(fl)}</span></h2>'
                         f'<a class="small" href="/apps">Buka Aplikasi</a></div>'
                         f'<div class="card" style="border-color:color-mix(in srgb,var(--err) 40%,var(--line))"><div class="list">{"".join(rows)}</div>'
                         f'<p class="mut small" style="margin:12px 0 0">Uninstall manual lewat Settings → Apps di komputer tersebut, lalu klik Pindai di menu Aplikasi. '
                         f'Item hilang sendiri setelah aplikasinya tidak terdeteksi lagi.</p>{more}</div>')
    log = ""
    if is_admin(user):
        rows = log_list()
        if rows:
            log = f'<div class="sec-head"><h2>Aktivitas terakhir</h2></div><div class="card log"><div class="list">{rows}</div></div>'
    body = (attention + '<div class="sec-head"><h2>Komputer</h2></div>' + "".join(cards) + log
            + '<p class="foot">Status diperbarui otomatis setiap 5 detik.</p>')
    return shell(user, csrf, "/", body, q, JS_STATUS)


def settings_page(user, csrf, q):
    tab = q.get("tab", [""])[0]
    if any(k in q for k in ("edit", "agent", "new")) or any(k.startswith("f_") and k != "f_u" for k in q):
        tab = "komputer"
    if "reset" in q or "f_u" in q:
        tab = "pengguna"
    if tab not in ("komputer", "pengguna", "umum"):
        tab = "komputer"
    tabs = "".join(f'<a href="/settings?tab={k}"{" aria-current=page" if k == tab else ""}>{t}</a>'
                   for k, t in (("komputer", "Komputer"), ("pengguna", "Pengguna"), ("umum", "Umum")))
    body = {"komputer": settings_devices, "pengguna": settings_users, "umum": settings_general}[tab](user, csrf, q)
    return shell(user, csrf, "/settings", f'<nav class="tabs" aria-label="Bagian pengaturan">{tabs}</nav>{body}', q)


def settings_devices(user, csrf, q):
    edit_id = q.get("edit", [""])[0]
    ed = next((d for d in CFG["devices"] if d["id"] == edit_id), None)
    f = {k: v[0] for k, v in q.items() if k.startswith("f_")}

    # ---- kartu pasang agen
    agent_card = ""
    aid, atok = q.get("agent", [""])[0], q.get("tok", [""])[0]
    adev = next((d for d in CFG["devices"] if d["id"] == aid), None)
    if adev and atok in AGENT_TOKENS and AGENT_TOKENS[atok][1] > time.time():
        try:
            panel = f"http://{local_ip_for(adev['ip'])}:{int(CFG.get('port', 8080))}"
        except OSError:
            panel = "http://IP-PANEL:8080"
        cmd = f"irm {panel}/agent/{atok}.ps1 | iex"
        remove = (f'<form method="post" action="/devices/agent-remove" '
                  f'{confirm("Tombol Matikan untuk " + adev["name"] + " akan hilang. Agen di Windows tetap terpasang sampai dihapus manual (lihat README).", "Lepas agen", "Lepas agen?")}>'
                  f'{hidden(csrf, id=adev["id"])}<button class="btn quiet danger sm">Lepas agen</button></form>')
        agent_card = f"""<section class="card" id="agent" style="border-color:var(--acc)">
<h2>Pasang agen Matikan di {E(adev['name'])}</h2>
<ol class="steps"><li>Di komputer <b>{E(adev['name'])}</b>, klik kanan tombol Start lalu pilih <b>Terminal (Admin)</b>.</li>
<li>Salin perintah di bawah, tempel di Terminal, lalu tekan Enter.</li>
<li>Setelah muncul tulisan hijau <b>Berhasil</b>, klik <b>Tes</b> pada komputer ini.</li></ol>
<div class="cmd"><input id="agentcmd" readonly value="{E(cmd)}" aria-label="Perintah pasang agen">
<button class="btn" type="button" data-copy="agentcmd">{icon('copy')}Salin</button></div>
<p class="mut small" style="margin:10px 0 12px">Perintah berlaku 15 menit. Agen hanya menerima perintah dari panel ini, dan setiap perintah ditandatangani kunci rahasia.</p>
<div class="acts"><a class="btn sm" href="/settings">Selesai</a>{remove}</div></section>"""

    # ---- daftar komputer
    rows = []
    for d in CFG["devices"]:
        has_agent = bool(d.get("agent_secret"))
        tag = agent_badge(d)
        v = d.get("agent_version")
        upd = (f'<form method="post" action="/devices/agent-update">{hidden(csrf, id=d["id"])}'
               f'<button class="btn sm primary" data-busy="Memperbarui…">Perbarui agen</button></form>'
               if v and MIN_UPDATABLE <= v < template_version() else "")
        rows.append(f"""<div class="row"><div class="row-main"><b>{E(d['name'])}</b>{tag}
<div class="meta"><span>{E(d.get('ip') or 'IP belum diisi')}</span><span class="mono">{E(d['mac'])}</span></div></div>
<div class="acts"><a class="btn sm" href="/settings?edit={quote(d['id'])}#form-dev">Ubah</a>
<form method="post" action="/devices/test">{hidden(csrf, id=d['id'])}<button class="btn sm" data-busy="Mengetes…" title="Cek ARP, ping, port, dan agen">Tes</button></form>
{upd}<form method="post" action="/devices/agent">{hidden(csrf, id=d['id'])}<button class="btn sm" title="Pasang / pasang ulang agen di komputer ini">{'Pasang ulang' if has_agent else 'Pasang agen'}</button></form>
{del_form('/devices/delete', csrf, d['name'] + ' akan dihapus dari panel. Data di komputer itu tidak terpengaruh.', 'Hapus ' + d['name'] + '?', id=d['id'])}</div></div>""")
    listing = (f'<div class="card"><div class="list">{"".join(rows)}</div></div>' if rows else
               f'<div class="card empty">{icon("monitor")}<p class="small" style="margin:8px 0 0">Belum ada komputer.</p></div>')

    # ---- form tambah / ubah
    src = ed or {}
    def dv(k, dflt=""):
        if f:
            return E(f.get("f_" + k, dflt))
        v = src.get(k, dflt)
        return E(", ".join(map(str, v)) if isinstance(v, list) else str(v))
    remote = dv("remote_url")
    remote = "" if remote == E(DEFAULT_REMOTE) else remote
    adv_open = " open" if (f and any(f.get("f_" + k) for k in ("id", "broadcast", "check_ports", "remote_url"))) else ""
    open_form = " open" if (ed or f or "new" in q or not CFG["devices"]) else ""
    title = f"Ubah {E(ed['name'])}" if ed else "Tambah komputer"
    form = f"""<form method="post" action="/devices/save">{hidden(csrf, orig=ed['id'] if ed else '')}
<label>Nama komputer<input name="name" value="{dv('name')}" required maxlength="60" placeholder="mis. Komputer Lab 1"></label>
<div class="grid">
<label>MAC address<input name="mac" value="{dv('mac')}" required class="mono" placeholder="mis. 3C:7C:3F:12:34:56" autocapitalize="characters" spellcheck="false">
<span class="hint">Dari <span class="mono">ipconfig /all</span>, bagian Ethernet → Physical Address.</span></label>
<label>IP komputer<input name="ip" value="{dv('ip')}" inputmode="decimal" placeholder="mis. 192.168.10.50" spellcheck="false">
<span class="hint">Untuk cek status & agen Matikan. Sebaiknya IP tetap.</span></label>
</div>
<details class="more"{adv_open}><summary>Pengaturan lanjutan</summary>
<div class="grid">
<label>ID singkat<input name="id" value="{dv('id')}" maxlength="32" placeholder="otomatis dari nama" spellcheck="false"></label>
<label>Alamat broadcast<input name="broadcast" value="{dv('broadcast')}" placeholder="otomatis dari IP" spellcheck="false"></label>
<label>Port WOL<input name="port" type="number" min="1" max="65535" value="{dv('port', '9')}"></label>
<label>Port untuk cek status<input name="check_ports" value="{dv('check_ports', '')}" placeholder="mis. 3389 (boleh kosong)">
<span class="hint">Status sudah dicek lewat ARP & ping.</span></label>
</div>
<label>Link tombol Buka Remote<input name="remote_url" value="{remote}" placeholder="{DEFAULT_REMOTE}" spellcheck="false">
<span class="hint">Kosongkan untuk memakai Chrome Remote Desktop.</span></label>
</details>
<div class="acts"><button class="btn primary" data-busy="Menyimpan…">{'Simpan perubahan' if ed else 'Tambah komputer'}</button>
{'<a class="btn quiet" href="/settings">Batal</a>' if (ed or f) else ''}</div></form>"""
    form_card = f"""<details class="card" id="form-dev"{open_form} style="padding:0">
<summary style="list-style:none;cursor:pointer;padding:14px 16px;display:flex;align-items:center;gap:8px;font-weight:600">{icon('plus')}{title}</summary>
<div style="padding:0 16px 16px">{form}</div></details>"""

    return (agent_card + f'<div class="sec-head"><h2>Daftar komputer</h2></div>{listing}' + form_card)


def settings_users(user, csrf, q):
    reset = q.get("reset", [""])[0] or q.get("f_u", [""])[0]
    target = reset if reset in CFG["users"] else ""
    rows = []
    for u, v in sorted(CFG["users"].items()):
        me = ' <span class="tag acc">Anda</span>' if u == user else ""
        role = "Admin" if v.get("role") == "admin" else "Pengguna"
        dl = "" if u == user else del_form("/users/delete", csrf, f"{u} tidak bisa masuk ke panel lagi.", f"Hapus pengguna {u}?", u=u)
        rows.append(f"""<div class="row"><div class="row-main"><b>{E(u)}</b>{me}<div class="mut small">{role}</div></div>
<div class="acts"><a class="btn sm" href="/settings?tab=pengguna&reset={quote(u)}#form-user">Ubah</a>{dl}</div></div>""")
    sel = lambda r: " selected" if target and CFG["users"][target].get("role") == r else ""
    uname = (f'<label>Nama pengguna<input value="{E(target)}" readonly><input type="hidden" name="u" value="{E(target)}"></label>' if target else
             f'<label>Nama pengguna<input name="u" required pattern="[A-Za-z0-9._\\-]{{3,32}}" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="mis. guru.tik">'
             f'<span class="hint">3–32 karakter: huruf, angka, titik, minus.</span></label>')
    form = f"""<section class="card" id="form-user"><h2>{('Ubah ' + E(target)) if target else 'Tambah pengguna'}</h2>
<form method="post" action="/users/save">{hidden(csrf)}
<div class="grid">{uname}
<label>Peran<select name="role"><option value="user"{sel('user')}>Pengguna</option><option value="admin"{sel('admin')}>Admin</option></select>
<span class="hint">Pengguna: menyalakan & mematikan. Admin: juga mengubah pengaturan.</span></label>
<label>{'Password baru' if target else 'Password'}<input name="p1" type="password" minlength="8" required autocomplete="new-password">
<span class="hint">Minimal 8 karakter.</span></label>
<label>Ulangi password<input name="p2" type="password" minlength="8" required autocomplete="new-password"></label>
</div><div class="acts"><button class="btn primary" data-busy="Menyimpan…">{'Simpan perubahan' if target else 'Tambah pengguna'}</button>
{'<a class="btn quiet" href="/settings?tab=pengguna">Batal</a>' if target else ''}</div></form></section>"""
    return f'<div class="sec-head"><h2>Daftar pengguna</h2></div><div class="card"><div class="list">{"".join(rows)}</div></div>{form}'


def settings_general(user, csrf, q):
    return f"""<section class="card"><h2>Umum</h2><form method="post" action="/settings/general">{hidden(csrf)}
<label class="check"><input type="checkbox" name="trust_proxy" value="1" {'checked' if CFG.get('trust_proxy') else ''}>
<span>Panel diakses lewat reverse proxy (NPMplus / Nginx)
<span class="hint">Centang jika panel dibuka lewat subdomain di NPMplus, agar IP asli pengunjung tercatat dan pembatasan login bekerja benar.</span></span></label>
<label style="max-width:220px">Lama sesi login<input name="session_hours" type="number" min="1" max="720" value="{int(CFG.get('session_hours', 12))}">
<span class="hint">Dalam jam (1–720).</span></label>
<button class="btn primary" data-busy="Menyimpan…">Simpan</button></form></section>"""


def app_meta(a, osdate="", source=True):
    bits = [a.get("version"), a.get("publisher")]
    if user_installed(a):
        bits.append(f"dipasang di akun {a.get('scope')}")
    elif a.get("kind") != "store":
        bits.append(a.get("scope"))
    if source:
        bits.append(dict(SOURCES)[app_source(a, osdate)])
    return " · ".join(E(b) for b in bits if b)


def uninstall_form(csrf, dev, a, back=False, label="Uninstall"):
    return (f'<form method="post" action="/apps/uninstall" '
            f'{confirm(a["name"] + " akan di-uninstall dari " + dev["name"] + ". Jika aplikasi sedang dibuka, aplikasi itu akan ditutup.", "Uninstall", "Uninstall " + a["name"] + "?")}>'
            f'{hidden(csrf, dev=dev["id"], app=a["id"], **({"back": back if isinstance(back, str) else dev["id"]} if back else {}))}'
            f'<button class="btn danger sm" data-busy="Menghapus…">{label}</button></form>')


def scan_label(dev_id):
    s = SCANS.get(dev_id)
    if not s:
        return '<span class="mut small">Belum dipindai</span>'
    t = fmt_time(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s["time"])))
    if s.get("error"):
        return f'<span class="small" style="color:var(--err)">{E(s["error"])}</span> <span class="mut small">· {E(t)}</span>'
    return f'<span class="mut small">Dipindai {E(t)} · {len(s.get("apps", []))} aplikasi</span>'


def apps_page(user, csrf, q):
    dev_id = q.get("dev", [""])[0]
    if dev_id:
        dev = next((d for d in CFG["devices"] if d["id"] == dev_id), None)
        if dev:
            return apps_device_page(user, csrf, q, dev)
    agents = [d for d in CFG["devices"] if d.get("agent_secret")]
    if not agents:
        body = (f'<div class="sec-head"><h2>Aplikasi</h2></div><div class="card empty">{icon("monitor")}'
                '<h3 style="margin:8px 0 4px">Belum ada komputer yang dipasangi agen</h3>'
                '<p class="small" style="margin:0 0 14px">Pemindai aplikasi berjalan lewat agen yang sama dengan tombol Matikan.</p>'
                '<a class="btn primary" href="/settings">Buka Pengaturan → Agen</a></div>')
        return shell(user, csrf, "/apps", body, q)

    # --- temuan
    groups = []
    for d in agents:
        items = flagged(d["id"])
        if not items:
            continue
        rows = []
        sd = SCANS.get(d["id"]) or {}
        for a, r in items:
            mode = ('<span class="tag bad">Hapus otomatis</span>' if r.get("auto") else '<span class="tag warn">Dilaporkan</span>')
            if r.get("auto") and PROTECTED.search(a.get("name", "")):
                mode = '<span class="tag">Dilindungi — hapus manual</span>'
            if a["id"] in (sd.get("failed") or {}):
                mode += ' <span class="tag bad">Gagal dihapus</span>'
            rows.append(f'<div class="row"><div class="row-main"><b>{E(a["name"])}</b> {mode}'
                        f'<div class="mut small">{app_meta(a, sd.get("osdate", ""))}</div></div>{uninstall_form(csrf, d, a)}</div>')
        groups.append(f'<div class="group"><div class="group-head"><h3>{E(d["name"])}</h3>{scan_label(d["id"])}</div>'
                      f'<div class="list">{"".join(rows)}</div></div>')
    if groups:
        finds = f'<div class="card">{"".join(groups)}</div>'
    elif CFG.get("app_rules"):
        finds = (f'<div class="card empty">{icon("check")}<p class="small" style="margin:8px 0 0">'
                 'Tidak ada aplikasi yang cocok dengan aturan di komputer yang sudah dipindai.</p></div>')
    else:
        finds = ('<div class="card empty"><p class="small" style="margin:0">Belum ada aturan. Tambahkan aturan di bawah, '
                 'misalnya <b>roblox</b> atau <b>Google Play Games</b>, agar aplikasi itu ditandai di sini.</p></div>')

    # --- riwayat hapus otomatis
    autos = sorted(((e, d) for d in agents for e in (SCANS.get(d["id"]) or {}).get("auto", [])),
                   key=lambda x: -x[0]["time"])[:8]
    auto_card = ""
    if autos:
        rows = "".join(
            f'<div class="row"><div class="row-main"><b>{E(e["name"])}</b> <span class="mut">di {E(d["name"])}</span>'
            f'<div class="small" style="color:var({"--ok" if e["ok"] else "--err"})">{E(e["msg"])}</div></div>'
            f'<time>{E(fmt_time(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["time"]))))}</time></div>' for e, d in autos)
        auto_card = f'<div class="sec-head"><h2>Hapus otomatis terakhir</h2></div><div class="card log"><div class="list">{rows}</div></div>'

    # --- komputer
    drows = "".join(
        f'<div class="row"><div class="row-main"><b>{E(d["name"])}</b><div>{scan_label(d["id"])}</div></div>'
        f'<div class="acts"><a class="btn sm" href="/apps?dev={quote(d["id"])}">Lihat aplikasi</a>'
        f'<form method="post" action="/apps/scan">{hidden(csrf, dev=d["id"])}<button class="btn sm" data-busy="Memindai…">Pindai</button></form></div></div>'
        for d in agents)
    others = len(CFG["devices"]) - len(agents)
    note = f'<p class="foot">{others} komputer belum dipasangi agen sehingga tidak ikut dipindai.</p>' if others else ""

    # --- aturan
    counts = {}
    for d in agents:
        for a in (SCANS.get(d["id"]) or {}).get("apps", []):
            r = match_rule(a)
            if r:
                c = counts.setdefault(r["id"], [0, set()])
                c[0] += 1
                c[1].add(d["id"])
    rrows = []
    for r in CFG.get("app_rules", []):
        c = counts.get(r["id"], [0, set()])
        mode = '<span class="tag bad">Hapus otomatis</span>' if r.get("auto") else '<span class="tag warn">Dilaporkan</span>'
        toggle = "Jadikan laporan saja" if r.get("auto") else "Jadikan hapus otomatis"
        tform = (f'<form method="post" action="/apps/rules/toggle" '
                 + ("" if r.get("auto") else confirm(f"Aplikasi yang cocok dengan '{r['pattern']}' akan langsung di-uninstall setiap kali komputer dipindai, tanpa konfirmasi.", "Aktifkan", "Hapus otomatis?"))
                 + f'>{hidden(csrf, rid=r["id"])}<button class="btn sm">{toggle}</button></form>')
        rrows.append(f'<div class="row"><div class="row-main"><b class="mono">{E(r["pattern"])}</b> {mode}'
                     f'<div class="mut small">Cocok {c[0]} aplikasi di {len(c[1])} komputer</div></div>'
                     f'<div class="acts">{tform}{del_form("/apps/rules/delete", csrf, "Aturan " + r["pattern"] + " akan dihapus. Aplikasi yang sudah terpasang tidak terpengaruh.", "Hapus aturan?", rid=r["id"])}</div></div>')
    rules_list = f'<div class="list">{"".join(rrows)}</div>' if rrows else '<p class="mut small" style="margin:0">Belum ada aturan.</p>'
    rule_form = f"""<form method="post" action="/apps/rules/add" style="margin-top:16px;padding-top:14px;border-top:1px solid var(--line)">{hidden(csrf)}
<div class="inline"><label>Nama aplikasi<input name="pattern" required maxlength="80" placeholder="mis. roblox" spellcheck="false"></label>
<label style="flex:0 1 220px">Tindakan<select name="mode"><option value="report">Laporkan saja</option><option value="auto">Hapus otomatis</option></select></label>
<button class="btn primary" style="margin-bottom:1px">Tambah aturan</button></div>
<p class="mut small" style="margin:8px 0 0">Tanpa tanda <span class="mono">*</span> berarti "nama mengandung". Huruf besar/kecil tidak dibedakan.
Contoh: <span class="mono">roblox</span>, <span class="mono">Google Play Games</span>, <span class="mono">*minecraft*</span>.
Aplikasi sistem (Windows, driver, .NET, Visual C++, Office, Edge) tidak pernah dihapus otomatis.</p></form>"""
    interval = f"""<form method="post" action="/apps/interval" class="inline" style="margin-top:14px">{hidden(csrf)}
<label style="flex:0 1 260px">Pindai otomatis setiap (menit)<input name="minutes" type="number" min="0" max="1440" value="{int(CFG.get('scan_minutes', 60))}"></label>
<button class="btn">Simpan</button></form><p class="mut small" style="margin:6px 0 0">0 = hanya saat tombol Pindai diklik.</p>"""

    body = f"""<div class="sec-head"><h2>Cocok dengan aturan</h2>
<form method="post" action="/apps/scan">{hidden(csrf, dev='semua')}<button class="btn sm" data-busy="Memulai…">Pindai semua sekarang</button></form></div>
{finds}{auto_card}
<div class="sec-head"><h2>Aturan</h2></div><div class="card">{rules_list}{rule_form}</div>
<div class="sec-head"><h2>Komputer</h2></div><div class="card"><div class="list">{drows}</div>{interval}</div>{note}"""
    return shell(user, csrf, "/apps", body, q)


def apps_device_page(user, csrf, q, dev):
    s = SCANS.get(dev["id"]) or {}
    apps, osdate = s.get("apps", []), s.get("osdate", "")
    failed = s.get("failed") or {}
    groups = {k: [] for k, _ in SOURCES}
    for a in apps:
        r = match_rule(a)
        tag = ""
        if r:
            tag = ' <span class="tag bad">Hapus otomatis</span>' if r.get("auto") else ' <span class="tag warn">Cocok aturan</span>'
            if r.get("auto") and PROTECTED.search(a.get("name", "")):
                tag = ' <span class="tag">Dilindungi — hapus manual</span>'
        if a["id"] in failed:
            tag += ' <span class="tag bad">Gagal dihapus</span>'
        if user_installed(a):
            tag += ' <span class="tag acc">Dipasang sendiri</span>'
        mk = "" if r else (f'<form method="post" action="/apps/rules/add">{hidden(csrf, pattern=a["name"], mode="report", dev=dev["id"])}'
                           f'<button class="btn quiet sm" title="Tandai aplikasi ini di semua komputer">Jadikan aturan</button></form>')
        groups[app_source(a, osdate)].append(
            f'<div class="row" data-name="{E((a.get("name","") + " " + (a.get("publisher") or "")).lower())}">'
            f'<div class="row-main"><b>{E(a["name"])}</b>{tag}<div class="mut small">{app_meta(a, osdate, source=False)}</div></div>'
            f'<div class="acts">{mk}{uninstall_form(csrf, dev, a, back=True)}</div></div>')
    hints = {"luar": "Dipasang dari installer di luar Store — paling perlu diperiksa. Label <b>Dipasang sendiri</b> berarti terpasang di satu akun tanpa hak admin.",
             "store": "Dipasang dari Microsoft Store oleh pengguna.",
             "bawaan": "Ikut Windows atau pabrikan komputer: aplikasi sistem, driver, runtime. Biasanya tidak perlu dihapus."}
    if not dev.get("agent_secret"):
        content = '<div class="card empty"><p class="small" style="margin:0">Komputer ini belum dipasangi agen. Buka Pengaturan → Agen.</p></div>'
    elif not s:
        content = '<div class="card empty"><p class="small" style="margin:0">Belum pernah dipindai. Klik <b>Pindai sekarang</b> saat komputer menyala.</p></div>'
    else:
        tabs = "".join(f'<a href="#g-{k}" data-g="{k}"{" aria-current=page" if k == "luar" else ""}>{t} <span class="mut">{len(groups[k])}</span></a>'
                       for k, t in SOURCES)
        none = '<p class="mut small" style="margin:0">Tidak ada.</p>'
        secs = "".join(
            f'<section class="grp" id="g-{k}"{"" if k == "luar" else " hidden"}><h3 class="grp-t" hidden style="margin:0 0 8px">{dict(SOURCES)[k]}</h3>'
            f'<p class="mut small grp-h" style="margin:0 0 10px">{hints[k]}</p>'
            f'<div class="card"><div class="list">{"".join(groups[k]) or none}</div></div></section>'
            for k, _ in SOURCES)
        content = (f'<nav class="tabs" aria-label="Kelompok aplikasi">{tabs}</nav>'
                   f'<div class="search"><input id="q" type="search" placeholder="Cari di semua kelompok…" aria-label="Cari aplikasi"></div>{secs}')
    js = """(function(){
var tabs=document.querySelectorAll('.tabs a[data-g]'),q=document.getElementById('q');
function show(g){tabs.forEach(function(t){t.toggleAttribute('aria-current',t.dataset.g===g);if(t.dataset.g===g)t.setAttribute('aria-current','page')});
 document.querySelectorAll('.grp').forEach(function(s){s.hidden=s.id!=='g-'+g})}
tabs.forEach(function(t){t.onclick=function(e){e.preventDefault();if(q)q.value='';filter();show(t.dataset.g);history.replaceState(null,'','#g-'+t.dataset.g)}});
if(location.hash.indexOf('#g-')===0)show(location.hash.slice(3));
var none=document.createElement('p');none.className='card empty small';none.textContent='Tidak ada aplikasi yang cocok.';none.hidden=true;
var first=document.querySelector('.grp');if(first)first.parentNode.insertBefore(none,first);
function filter(){var v=q?q.value.trim().toLowerCase():'',total=0;
 document.querySelectorAll('.grp').forEach(function(s){var n=0,firstRow=null;
  s.querySelectorAll('.row').forEach(function(r){var m=!v||r.dataset.name.indexOf(v)>=0;r.style.display=m?'':'none';r.style.borderTop='';
   if(m){n++;if(!firstRow){firstRow=r}}});
  if(firstRow&&v){firstRow.style.borderTop='0';firstRow.style.paddingTop='0'}else if(firstRow){firstRow.style.paddingTop=''}
  s.querySelector('.grp-t').hidden=!v;s.querySelector('.grp-h').hidden=!!v;
  if(v)s.hidden=n===0;total+=n});
 none.hidden=!(v&&total===0);
 if(!v){var cur=document.querySelector('.tabs a[aria-current]');if(cur)show(cur.dataset.g)}}
if(q)q.addEventListener('input',filter);})();"""
    body = f"""<p style="margin:0 0 8px"><a href="/apps" class="small">← Semua komputer</a></p>
<div class="sec-head" style="margin-top:0"><div><h2 style="color:var(--fg);font-size:18px">{E(dev['name'])}</h2>{scan_label(dev['id'])}</div>
<form method="post" action="/apps/scan">{hidden(csrf, dev=dev['id'], back=dev['id'])}<button class="btn primary sm" data-busy="Memindai…">Pindai sekarang</button></form></div>
{content}"""
    return shell(user, csrf, "/apps", body, q, js)


def fmt_age(ts):
    if not ts:
        return "belum pernah"
    return fmt_time(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)))


def fmt_uptime(sec):
    try:
        s = int(sec)
    except (TypeError, ValueError):
        return ""
    d, h = s // 86400, s % 86400 // 3600
    return f"menyala {d} hari {h} jam" if d else f"menyala {h} jam {s % 3600 // 60} menit"


SEC_TAG = ' <span class="tag bad">keamanan</span>'


def job_failure(vm_id, app_dir=""):
    """Baris error pertama di log pekerjaan VM (+ baris lanjutannya) dan saran bila penyebabnya dikenali."""
    try:
        with open(vm_log_path(vm_id), encoding="utf-8", errors="replace") as f:
            lines = f.read()[-60000:].splitlines()
    except OSError:
        return "", ""
    for i, line in enumerate(lines):
        if re.match(r"\s*(error|fatal|E)\s*:", line, re.I):
            follow = [l.strip() for l in lines[i + 1:i + 4] if l.startswith(("\t", "  "))]
            reason = " ".join([line.strip()] + follow)
            hint = ""
            if "would be overwritten by merge" in line:
                hint = (f"File lokal di VM bentrok dengan versi baru di repo. Singkirkan dulu lewat Terminal: "
                        f"cd {app_dir or '/var/www/APLIKASI'} && mv {' '.join(follow) or 'NAMA_FILE'} /root/ "
                        f"— lalu klik Update aplikasi lagi.")
            return reason[:300], hint
    return "", ""


def servers_page(user, csrf, q):
    vms = CFG.get("vms", [])
    install_card = ""
    vid, vtok = q.get("install", [""])[0], q.get("tok", [""])[0]
    ivm = next((v for v in vms if v["id"] == vid), None)
    if ivm and vtok in VM_TOKENS and VM_TOKENS[vtok][1] > time.time():
        try:
            panel = f"http://{local_ip_for(ivm['host'])}:{int(CFG.get('port', 8080))}"
        except OSError:
            panel = "http://IP-PANEL:8080"
        cmd = f"curl -fsSL {panel}/vm/{vtok}.sh | bash"
        install_card = f"""<section class="card" id="install" style="border-color:var(--acc)">
<h2>Sambungkan {E(ivm['name'])} ke panel</h2>
<ol class="steps"><li>Buka konsol VM <b>{E(ivm['name'])}</b> (Proxmox → VM → Console, atau SSH) dan masuk sebagai <b>root</b> (<span class="mono">sudo -i</span>).</li>
<li>Salin perintah di bawah, tempel, lalu tekan Enter.</li>
<li>Setelah muncul <b>Berhasil</b>, klik <b>Cek</b> pada VM ini.</li></ol>
<div class="cmd"><input id="vmcmd" readonly value="{E(cmd)}" aria-label="Perintah pasang"><button class="btn" type="button" data-copy="vmcmd">{icon('copy')}Salin</button></div>
<p class="mut small" style="margin:10px 0 12px">Perintah berlaku 15 menit. Panel hanya bisa menjalankan <span class="mono">wol-update</span> (cek, update OS, update aplikasi, reboot)
di VM ini, hanya dari IP panel. Folder aplikasi dideteksi otomatis dari <span class="mono">/var/www/*/deploy/update.sh</span>
dan bisa diubah di <span class="mono">/etc/wol-update.conf</span>.</p>
<a class="btn sm" href="/servers">Selesai</a></section>"""

    cards = []
    for vm in vms:
        st = VMSTATE.get(vm["id"]) or {}
        d = st.get("data") or {}
        job = VM_JOBS.get(vm["id"])
        running = vm_job_running(vm["id"])
        vid_e = E(vm["id"])
        # status ringkas
        tags = []
        if st.get("error"):
            tags.append(f'<span class="tag bad">{E(st["error"])}</span>')
        if d:
            up = int(d.get("upgradable") or 0)
            sec = int(d.get("security") or 0)
            if up:
                tags.append(f'<span class="tag {"bad" if sec else "warn"}">{up} pembaruan OS' + (f" · {sec} keamanan" if sec else "") + "</span>")
            else:
                tags.append('<span class="tag ok">OS terbaru</span>')
            if d.get("app"):
                b = d.get("app_behind", "?")
                if b not in ("0", "?"):
                    tags.append(f'<span class="tag warn">{E(b)} commit baru</span>')
                elif b == "0":
                    tags.append('<span class="tag ok">Kode terbaru</span>')
            hv, tv = int(d.get("version") or 0), vm_template_version()
            if hv and hv < tv:
                tags.append(f'<span class="tag warn">wol-update v{hv} · ada v{tv}</span>' if hv >= VM_SELF_UPDATE_MIN else
                            f'<span class="tag warn" title="Versi ini belum bisa memperbarui dirinya">wol-update v{hv} · Lainnya → Pasang ulang sekali</span>')
            if time.time() - st.get("rebooting", 0) < 900:
                tags.insert(0, '<span class="pill wait"><span class="dot"></span><span>Sedang restart… menunggu VM kembali</span></span>')
            elif d.get("reboot") == "1":
                tags.append('<span class="tag bad">Perlu reboot</span>')
            if d.get("apt_error"):
                tags.append(f'<span class="tag bad" title="{E(d["apt_error"])}">apt gagal</span>')
            if d.get("app_error"):
                tags.append(f'<span class="tag bad" title="{E(d["app_error"])}">git fetch gagal</span>')
        meta = [E(vm["host"])]
        if d.get("os"):
            meta.append(E(d["os"]))
        if d.get("uptime"):
            meta.append(fmt_uptime(d["uptime"]))
        if d.get("disk"):
            meta.append(f"disk {E(d['disk'])}")
        app_line = ""
        if d.get("app"):
            h = d.get("app_head") or {}
            app_line = (f'<div class="mut small">Aplikasi <span class="mono">{E(d["app"])}</span> · {E(d.get("app_branch", ""))} @ '
                        f'<span class="mono">{E(h.get("hash", "?"))}</span> {E(h.get("msg", ""))[:70]}</div>')
        elif d:
            app_line = '<div class="mut small">Tidak ada aplikasi dengan deploy/update.sh — hanya update OS.</div>'

        # tombol
        def act(action, label, cls, text, title):
            dis = " disabled" if running else ""
            return (f'<form method="post" action="/servers/run" {confirm(text, label, title)}>{hidden(csrf, id=vm["id"], action=action)}'
                    f'<button class="btn sm {cls}"{dis}>{label}</button></form>')
        btns = [f'<form method="post" action="/servers/check">{hidden(csrf, id=vm["id"])}'
                f'<button class="btn sm" data-busy="Mengecek…"{" disabled" if running else ""}>Cek</button></form>']
        if d:
            up = int(d.get("upgradable") or 0)
            btns.append(act("os-upgrade", "Update OS", "primary" if up else "",
                            f"apt-get upgrade akan dijalankan di {vm['name']}" + (f" ({up} paket)." if up else ".") +
                            " Layanan yang paketnya diperbarui bisa restart sebentar.", f"Update OS {vm['name']}?"))
            if d.get("app") and d.get("app_script") == "1":
                b = d.get("app_behind", "?")
                btns.append(act("app-update", "Update aplikasi", "primary" if b not in ("0", "?") else "",
                                f"deploy/update.sh akan dijalankan: backup database, mode pemeliharaan, git pull, composer, migrasi, "
                                f"lalu aplikasi aktif lagi. Aplikasi tidak bisa diakses selama ±1 menit.", f"Update aplikasi di {vm['name']}?"))
        more_btns = []
        if d and VM_SELF_UPDATE_MIN <= int(d.get("version") or 0) < vm_template_version():
            btns.append(act("self-update", "Perbarui wol-update", "primary",
                            f"{vm['name']} akan mengunduh wol-update versi {vm_template_version()} dari repo resmi di GitHub, "
                            "lalu menggantikan versi lama.", f"Perbarui wol-update di {vm['name']}?"))
        if d:
            (btns if d.get("reboot") == "1" else more_btns).append(
                act("reboot", "Reboot", "danger" if d.get("reboot") == "1" else "quiet",
                    f"{vm['name']} akan restart 1 menit lagi. Aplikasi di VM ini tidak bisa diakses selama restart.", f"Reboot {vm['name']}?"))
        if vm.get("terminal"):
            btns.insert(1, f'<a class="btn sm" href="/terminal?vm={quote(vm["id"])}">Terminal</a>')
            more_btns.append(f'<form method="post" action="/servers/terminal" {confirm("Panel tidak lagi bisa membuka terminal ke " + vm["name"] + ". Jalankan perintah pasang yang muncul di VM itu untuk mencabut kunci terminalnya.", "Cabut", "Cabut izin terminal?")}>'
                        f'{hidden(csrf, id=vm["id"])}<button class="btn sm quiet">Cabut terminal</button></form>')
        else:
            more_btns.append(f'<form method="post" action="/servers/terminal" {confirm("Panel akan bisa membuka shell root ke " + vm["name"] + " dari jaringan sekolah. Setelah ini jalankan perintah pasang yang muncul di VM itu.", "Izinkan", "Izinkan terminal?")}>'
                        f'{hidden(csrf, id=vm["id"])}<button class="btn sm quiet">Izinkan terminal</button></form>')
        more_btns.append(f'<form method="post" action="/servers/install">{hidden(csrf, id=vm["id"])}<button class="btn sm quiet">Pasang ulang</button></form>')
        more_btns.append(f'<a class="btn sm quiet" href="/servers?edit={quote(vm["id"])}#form-vm">Ubah</a>')
        more_btns.append(del_form("/servers/delete", csrf, f"{vm['name']} dihapus dari panel. Akses SSH panel di VM tetap ada sampai dihapus dari /root/.ssh/authorized_keys.",
                                  f"Hapus {vm['name']}?", id=vm["id"]))
        btns.append(f'<details class="menu push"><summary class="btn sm quiet">Lainnya ▾</summary><div class="menu-pop">{"".join(more_btns)}</div></details>')

        # detail paket & commit
        detail = ""
        if d.get("pkgs") or d.get("commits"):
            pk = "".join(f'<div class="row"><div class="row-main"><b class="mono">{E(p["name"])}</b>'
                         f'{SEC_TAG if p["sec"] else ""}'
                         f'<div class="mut small mono">{E(p["from"])} → {E(p["to"])}</div></div></div>' for p in d.get("pkgs", [])[:100])
            cm = "".join(f'<div class="row"><div class="row-main"><span class="mono">{E(c["hash"])}</span> {E(c["msg"])}'
                         f'<div class="mut small">{E(fmt_age(c["time"]))}</div></div></div>' for c in d.get("commits", []))
            more = f'<p class="mut small">dan {len(d["pkgs"]) - 100} paket lainnya.</p>' if len(d.get("pkgs", [])) > 100 else ""
            detail = (f'<details class="more" style="margin:0"><summary>Rincian pembaruan</summary>'
                      + (f'<h3 style="margin:0 0 6px">Commit baru</h3><div class="list" style="margin-bottom:14px">{cm}</div>' if cm else "")
                      + (f'<h3 style="margin:0 0 6px">Paket OS</h3><div class="list">{pk}</div>{more}' if pk else "")
                      + '</details>')
        # status / log pekerjaan
        lj = st.get("last_job")
        jobline = ""
        if lj and not running:
            ok = lj.get("rc") == 0
            jobline = (f'<div class="small" style="color:var({"--ok" if ok else "--err"})">{E(VM_ACTIONS.get(lj["action"], lj["action"]))} '
                       f'{"berhasil" if ok else "gagal"} · {E(fmt_age(lj.get("end")))} oleh {E(lj.get("by", ""))} · '
                       f'<a href="#" data-log="{vid_e}">lihat log</a></div>')
            reason, hint = ("", "") if ok else job_failure(vm["id"], d.get("app", ""))
            if reason:
                jobline += (f'<div class="flash err" style="margin:8px 0 0">{icon("alert")}<div><span class="mono small">{E(reason)}</span>'
                            + (f'<div class="small" style="margin-top:4px;color:var(--fg)">{E(hint)}</div>' if hint else "") + '</div></div>')
        logbox = (f'<div class="joblog" id="job-{vid_e}" data-vm="{vid_e}" data-running="{"1" if running else "0"}"'
                  f'{"" if running else " hidden"}><div class="small" style="margin-bottom:6px"><b class="jobtitle">'
                  f'{E(VM_ACTIONS.get(job["action"], "") if job else "")}</b> <span class="mut jobstate">{"sedang berjalan…" if running else ""}</span></div>'
                  f'<pre class="log"></pre></div>')
        cards.append(f"""<article class="card dev vm" id="vm-{vid_e}">
<div class="dev-head"><div><h2>{E(vm['name'])}</h2><div class="meta">{' · '.join(meta)}</div>{app_line}
<div class="mut small">Dicek {E(fmt_age(st.get('checked')))}</div></div></div>
<div class="acts">{''.join(tags) or '<span class="tag">Belum dicek</span>'}</div>
{jobline}{logbox}{detail}
<div class="dev-acts">{''.join(btns)}</div></article>""")

    if not cards:
        cards.append(f'<div class="card empty">{icon("monitor")}<h3 style="margin:8px 0 4px">Belum ada VM</h3>'
                     '<p class="small" style="margin:0">Tambahkan VM aplikasi (Pusat, Absensi, BK, …) di bawah.</p></div>')
    ed = next((v for v in vms if v["id"] == q.get("edit", [""])[0]), None)
    fv = lambda k, dflt="": E(q[f"f_{k}"][0] if f"f_{k}" in q else str((ed or {}).get(k, dflt)))
    add = f"""<details class="card" id="form-vm" style="padding:0"{" open" if not vms or ed or q.get("f_name") else ""}>
<summary style="list-style:none;cursor:pointer;padding:14px 16px;display:flex;align-items:center;gap:8px;font-weight:600">{icon('plus') if not ed else ''}{'Ubah ' + E(ed['name']) if ed else 'Tambah VM'}</summary>
<form method="post" action="/servers/add" style="padding:0 16px 16px">{hidden(csrf, orig=ed['id'] if ed else '')}
<div class="grid"><label>Nama<input name="name" required maxlength="60" placeholder="mis. VM Absensi" value="{fv('name')}"></label>
<label>IP / host<input name="host" required maxlength="100" placeholder="mis. 192.168.10.21" spellcheck="false" value="{fv('host')}"></label>
<label>Port SSH<input name="port" type="number" min="1" max="65535" value="{fv('port', '22')}"></label></div>
<div class="acts"><button class="btn primary" data-busy="Menyimpan…">{'Simpan perubahan' if ed else 'Tambah VM'}</button>
{'<a class="btn quiet" href="/servers">Batal</a>' if ed else ''}</div></form></details>"""
    interval = f"""<form method="post" action="/servers/interval" class="inline" style="margin-top:4px">{hidden(csrf)}
<label style="flex:0 1 260px">Cek otomatis setiap (jam)<input name="hours" type="number" min="0" max="168" value="{E(str(CFG.get('vm_check_hours', 6)))}"></label>
<button class="btn">Simpan</button></form><p class="mut small" style="margin:6px 0 0">0 = hanya saat tombol Cek diklik. Update tetap dijalankan manual.</p>"""
    head = (f'<div class="sec-head"><h2>Server / VM</h2><form method="post" action="/servers/check">{hidden(csrf, id="semua")}'
            f'<button class="btn sm" data-busy="Memulai…">Cek semua</button></form></div>') if vms else '<div class="sec-head"><h2>Server / VM</h2></div>'
    js = """(function(){
function poll(box){var id=box.dataset.vm,pre=box.querySelector('pre'),state=box.querySelector('.jobstate');
 fetch('/api/vmjob?id='+encodeURIComponent(id),{cache:'no-store'}).then(function(r){return r.json()}).then(function(j){
  var atBottom=pre.scrollTop+pre.clientHeight>=pre.scrollHeight-20;pre.textContent=j.log||'';if(atBottom)pre.scrollTop=pre.scrollHeight;
  if(j.title)box.querySelector('.jobtitle').textContent=j.title;
  if(j.running){state.textContent='sedang berjalan…';setTimeout(function(){poll(box)},2000)}
  else if(box.dataset.running==='1'){state.textContent=j.rc===0?'selesai':'gagal (kode '+j.rc+')';setTimeout(function(){location.reload()},2500)}
 }).catch(function(){setTimeout(function(){poll(box)},4000)})}
document.querySelectorAll('.joblog[data-running="1"]').forEach(poll);
if(document.querySelector('.vm .pill.wait'))setTimeout(function(){if(!document.querySelector('details.menu[open],dialog[open]'))location.reload()},15000);
document.addEventListener('click',function(e){document.querySelectorAll('details.menu[open]').forEach(function(m){if(!m.contains(e.target))m.open=false})});
document.querySelectorAll('[data-log]').forEach(function(a){a.onclick=function(e){e.preventDefault();
 var b=document.getElementById('job-'+a.dataset.log);b.hidden=!b.hidden;if(!b.hidden)poll(b)}});
})();"""
    body = install_card + head + "".join(cards) + add + f'<div class="card">{interval}</div>'
    return shell(user, csrf, "/servers", body, q, js)


TERM_JS = """
(function(){
var el=document.getElementById('term');if(!el)return;
var csrf=el.dataset.csrf,sid=null,since=0,alive=false,q=[],sending=false;
var stat=document.getElementById('tstat'),sel=document.getElementById('tvm'),openBtn=document.getElementById('topen'),closeBtn=document.getElementById('tclose');
var term=new Terminal({cursorBlink:true,fontSize:14,scrollback:5000,fontFamily:'ui-monospace,"Cascadia Mono",Consolas,monospace',
  theme:{background:'#0d1117',foreground:'#d1d9e0',cursor:'#d1d9e0',selectionBackground:'#264f78'}});
var fit=new FitAddon.FitAddon();term.loadAddon(fit);term.open(el);fit.fit();
term.writeln('Pilih VM lalu klik Buka. Sesi direkam dan ditutup otomatis setelah 30 menit tanpa aktivitas.');
function setStat(t,cls){stat.textContent=t;stat.className='pill '+(cls||'')}
function post(url,body,type){return fetch(url,{method:'POST',headers:{'X-CSRF':csrf,'Content-Type':type||'application/x-www-form-urlencoded'},body:body})}
function b64(s){var bin=atob(s),u=new Uint8Array(bin.length);for(var i=0;i<bin.length;i++)u[i]=bin.charCodeAt(i);return u}
function poll(){if(!sid)return;var my=sid;
 fetch('/terminal/out?sid='+encodeURIComponent(my)+'&since='+since,{cache:'no-store'}).then(function(r){
  if(r.status===401||r.status===403){throw new Error('auth')}return r.json()}).then(function(j){
  if(my!==sid)return;if(j.d)term.write(b64(j.d));since=j.n;
  if(j.alive){poll()}else{alive=false;setStat('Terputus','');openBtn.disabled=false;closeBtn.disabled=true;sel.disabled=false}
 }).catch(function(e){if(e.message==='auth'){setStat('Sesi kunci habis — muat ulang halaman','bad');return}setTimeout(poll,2000)})}
function flush(){if(sending||!q.length||!sid)return;sending=true;var data=q.join('');q=[];
 post('/terminal/in?sid='+encodeURIComponent(sid),data,'text/plain;charset=utf-8').finally(function(){sending=false;flush()})}
term.onData(function(d){if(!alive)return;q.push(d);flush()});
var rt;function resize(){fit.fit();if(!sid)return;clearTimeout(rt);rt=setTimeout(function(){
 post('/terminal/resize','sid='+encodeURIComponent(sid)+'&rows='+term.rows+'&cols='+term.cols)},150)}
window.addEventListener('resize',resize);
openBtn.onclick=function(){openBtn.disabled=true;sel.disabled=true;setStat('Menyambungkan…','wait');term.reset();
 post('/terminal/open','vm='+encodeURIComponent(sel.value)+'&rows='+term.rows+'&cols='+term.cols).then(function(r){return r.json()}).then(function(j){
  if(!j.sid){term.writeln('\\r\\n'+(j.error||'Gagal membuka terminal.'));setStat('Gagal','bad');openBtn.disabled=false;sel.disabled=false;return}
  sid=j.sid;since=0;alive=true;closeBtn.disabled=false;setStat('Tersambung ke '+sel.options[sel.selectedIndex].text,'on');term.focus();poll();
 })};
closeBtn.onclick=function(){if(sid)post('/terminal/close','sid='+encodeURIComponent(sid));closeBtn.disabled=true};
window.addEventListener('beforeunload',function(){if(sid&&alive)navigator.sendBeacon&&fetch('/terminal/close',{method:'POST',keepalive:true,
 headers:{'X-CSRF':csrf,'Content-Type':'application/x-www-form-urlencoded'},body:'sid='+encodeURIComponent(sid)})});
})();
"""


def terminal_page(user, csrf, q, lan_ok, unlocked, panel_url=""):
    vms = [v for v in CFG.get("vms", []) if v.get("terminal")]
    head = '<div class="sec-head"><h2>Terminal</h2></div>'
    if not lan_ok:
        body = (head + f'<div class="card">{icon("alert")} <b>Terminal hanya bisa dibuka dari jaringan sekolah.</b>'
                '<p class="mut small" style="margin:8px 0 0">Untuk keamanan, terminal ditolak bila panel dibuka lewat internet / NPMplus. '
                f'Buka panel langsung dari komputer di jaringan sekolah{": " + E(panel_url) if panel_url else ""}.</p></div>')
        return shell(user, csrf, "/terminal", body, q)
    if not vms:
        body = (head + f'<div class="card empty">{icon("monitor")}<h3 style="margin:8px 0 4px">Belum ada VM yang diizinkan terminal</h3>'
                '<p class="small" style="margin:0 0 14px">Di menu Server, klik <b>Izinkan terminal</b> pada VM, lalu jalankan perintah pasangnya di VM itu.</p>'
                '<a class="btn primary" href="/servers">Buka Server</a></div>')
        return shell(user, csrf, "/terminal", body, q)
    if not unlocked:
        body = head + f"""<section class="card" style="max-width:420px"><h2>Konfirmasi password</h2>
<p class="mut small" style="margin:0 0 12px">Terminal memberi akses root ke VM. Ketik ulang password akun <b>{E(user)}</b> untuk membukanya selama 30 menit.</p>
<form method="post" action="/terminal/unlock">{hidden(csrf)}<input type="text" name="username" value="{E(user)}" autocomplete="username" hidden>
<label>Password<input name="p" type="password" required autofocus autocomplete="current-password"></label>
<button class="btn primary" data-busy="Memeriksa…">Buka terminal</button></form></section>"""
        return shell(user, csrf, "/terminal", body, q)
    pre = q.get("vm", [""])[0]
    opts = "".join(f'<option value="{E(v["id"])}"{" selected" if v["id"] == pre else ""}>{E(v["name"])} ({E(v["host"])})</option>' for v in vms)
    body = f"""<link rel="stylesheet" href="/static/xterm.css">
<div class="sec-head"><h2>Terminal</h2><span id="tstat" class="pill">Belum tersambung</span></div>
<div class="card" style="padding:12px">
<div class="inline" style="margin-bottom:10px"><label style="flex:1 1 220px;margin:0">VM<select id="tvm" style="margin-top:4px">{opts}</select></label>
<button class="btn primary" id="topen" type="button">Buka</button><button class="btn" id="tclose" type="button" disabled>Putuskan</button></div>
<div id="term" data-csrf="{csrf}" style="height:min(70vh,560px);background:#0d1117;border-radius:9px;padding:6px;overflow:hidden"></div>
<p class="mut small" style="margin:10px 0 0">Masuk sebagai root. Semua tampilan sesi direkam di panel (<span class="mono">vmlogs/terminal/</span>).
Salin: pilih teks · Tempel: Ctrl+Shift+V / klik kanan.</p></div>
<script src="/static/xterm.js"></script><script src="/static/xterm-addon-fit.js"></script>"""
    return shell(user, csrf, "/terminal", body.replace('"wrap"', '"wrap"'), q, TERM_JS)


def account_page(user, csrf, q):
    body = f"""<div class="sec-head"><h2>Akun</h2></div><section class="card"><h2>Ganti password</h2>
<form method="post" action="/account">{hidden(csrf)}
<input type="text" name="username" value="{E(user)}" autocomplete="username" hidden>
<label>Password lama<input name="old" type="password" required autocomplete="current-password"></label>
<div class="grid"><label>Password baru<input name="p1" type="password" minlength="8" required autocomplete="new-password">
<span class="hint">Minimal 8 karakter.</span></label>
<label>Ulangi password baru<input name="p2" type="password" minlength="8" required autocomplete="new-password"></label></div>
<button class="btn primary" data-busy="Menyimpan…">Ganti password</button></form>
<p class="mut small" style="margin:12px 0 0">Setelah password diganti, sesi di perangkat lain otomatis keluar.</p></section>"""
    return shell(user, csrf, "/account", body, q)


# --------------------------------------------------------------- handler
class Handler(BaseHTTPRequestHandler):
    server_version = "WOLPanel"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def client_ip(self):
        if CFG.get("trust_proxy"):
            xff = self.headers.get("X-Forwarded-For")
            if xff:
                return xff.split(",")[0].strip()
        return self.client_address[0]

    def session(self):
        c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        if COOKIE in c:
            tok = c[COOKIE].value
            u = verify_session(tok)
            if u:
                return u, tok
        return None, None

    def _send(self, status, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, loc, extra=None):
        self.send_response(303)
        self.send_header("Location", loc)
        self.send_header("Content-Length", "0")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()

    def back(self, path, msg, err=False, **extra):
        params = {"msg": msg, **extra}
        if err:
            params["err"] = "1"
        self.redirect(f"{path}?{urlencode(params)}")

    def cookie_header(self, value, max_age):
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "").lower() == "https" else ""
        return ("Set-Cookie", f"{COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}")

    # ---------------- GET
    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/login":
            return self._send(200, login_page())
        if url.path in ("/static/xterm.js", "/static/xterm-addon-fit.js", "/static/xterm.css"):
            try:
                with open(os.path.join(BASE, url.path.lstrip("/")), "rb") as f:
                    data = f.read()
            except OSError:
                return self._send(404, "Tidak ditemukan")
            ctype = "text/css; charset=utf-8" if url.path.endswith(".css") else "application/javascript; charset=utf-8"
            return self._send(200, data, ctype, [("Cache-Control", "public, max-age=86400")])
        m = re.fullmatch(r"/vm/([A-Za-z0-9_-]{20,64})\.sh", url.path)
        if m:  # skrip pasang akses update untuk VM (token sementara)
            ent = VM_TOKENS.get(m.group(1))
            vm = ent and ent[1] > time.time() and next((v for v in CFG["vms"] if v["id"] == ent[0]), None)
            if not vm:
                return self._send(200, "echo 'Perintah sudah kedaluwarsa. Buat ulang dari WOL Panel: Server -> Pasang ulang.'; exit 1\n",
                                  "text/plain; charset=utf-8")
            write_log("-", "unduh-vm", vm["id"], self.client_ip())
            return self._send(200, vm_install_script(vm), "text/plain; charset=utf-8")
        m = re.fullmatch(r"/agent/([A-Za-z0-9_-]{20,64})\.ps1", url.path)
        if m:  # unduh pemasang agen memakai token sementara (tanpa login, diambil dari komputer tujuan)
            ent = AGENT_TOKENS.get(m.group(1))
            dev = ent and ent[1] > time.time() and next((d for d in CFG["devices"] if d["id"] == ent[0]), None)
            if not dev or not dev.get("agent_secret"):
                return self._send(200, "Write-Host 'Perintah sudah kedaluwarsa. Buat ulang dari WOL Panel: Pengaturan -> Agen.' -ForegroundColor Red\n",
                                  "text/plain; charset=utf-8")
            write_log("-", "unduh-agen", dev["id"], self.client_ip())
            return self._send(200, agent_script(dev), "text/plain; charset=utf-8")
        user, tok = self.session()
        if not user:
            if url.path.startswith("/api/"):
                return self._send(401, '{"error":"login"}', "application/json")
            return self.redirect("/login")
        q = parse_qs(url.query)
        csrf = csrf_for(tok)
        if url.path == "/":
            return self._send(200, home_page(user, csrf, q))
        if url.path == "/api/status":
            return self._send(200, json.dumps(all_status()), "application/json")
        if url.path == "/account":
            return self._send(200, account_page(user, csrf, q))
        if url.path == "/settings":
            if not is_admin(user):
                return self.redirect("/")
            return self._send(200, settings_page(user, csrf, q))
        if url.path == "/apps":
            if not is_admin(user):
                return self.redirect("/")
            return self._send(200, apps_page(user, csrf, q))
        if url.path == "/servers":
            if not is_admin(user):
                return self.redirect("/")
            return self._send(200, servers_page(user, csrf, q))
        if url.path == "/terminal":
            if not is_admin(user):
                return self.redirect("/")
            panel = f"http://{self.headers.get('Host', '').split(':')[0] or 'IP-panel'}:{int(CFG.get('port', 8080))}"
            return self._send(200, terminal_page(user, csrf, q, self.lan_direct(), term_unlocked(tok),
                                                 "" if self.lan_direct() else "http://<IP container panel>:" + str(int(CFG.get('port', 8080)))))
        if url.path == "/terminal/out":
            t = self.term_session(user, tok, q.get("sid", [""])[0])
            if not t:
                return self._send(403, '{"error":"sesi"}', "application/json")
            try:
                since = int(q.get("since", ["0"])[0])
            except ValueError:
                since = 0
            data, nxt, alive = t.read(since)
            return self._send(200, json.dumps({"d": base64.b64encode(data).decode(), "n": nxt, "alive": alive}), "application/json")
        if url.path == "/api/vmjob":
            if not is_admin(user):
                return self._send(403, "{}", "application/json")
            vid = q.get("id", [""])[0]
            job = VM_JOBS.get(vid) or (VMSTATE.get(vid) or {}).get("last_job") or {}
            try:
                with open(vm_log_path(vid), encoding="utf-8", errors="replace") as f:
                    log = f.read()[-60000:]
            except (OSError, ValueError):
                log = ""
            return self._send(200, json.dumps({"running": vm_job_running(vid), "rc": job.get("rc"),
                                               "title": VM_ACTIONS.get(job.get("action"), ""), "log": log}), "application/json")
        self._send(404, page("Tidak ditemukan", '<p>Halaman tidak ditemukan. <a href="/">Kembali</a></p>'))

    # ---------------- POST
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 20_000:
            return self._send(413, "Terlalu besar")
        raw = self.rfile.read(n)
        path = urlparse(self.path).path
        form = {} if path == "/terminal/in" else \
            {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True).items()}
        ip = self.client_ip()

        if path == "/login":
            return self.do_login(form, ip)

        user, tok = self.session()
        if path.startswith("/terminal/") and path != "/terminal/unlock":
            return self.do_terminal_api(path, raw, form, user, tok)
        if not user:
            return self.redirect("/login")
        if not hmac.compare_digest(form.get("csrf", ""), csrf_for(tok)):
            return self._send(403, page("Ditolak", '<p>Sesi kedaluwarsa, silakan <a href="/">muat ulang halaman</a>.</p>'))

        if path == "/logout":
            return self.redirect("/login", [self.cookie_header("", 0)])
        if path == "/wake":
            return self.do_wake(form, user, ip)
        if path == "/shutdown":
            return self.do_shutdown(form, user, ip)
        if path == "/account":
            return self.do_account(form, user, ip)

        if not is_admin(user):
            return self._send(403, page("Ditolak", "<p>Hanya admin yang boleh mengubah pengaturan.</p>"))
        if path == "/devices/test":
            dev = next((d for d in CFG["devices"] if d["id"] == form.get("id")), None)
            if not dev:
                return self.back("/settings", "Komputer tidak ditemukan.", True)
            return self.back("/settings", diagnose(dev))
        if path == "/apps/scan":
            return self.do_apps_scan(form, user, ip)
        if path == "/servers/check":
            return self.do_vm_check(form, user, ip)
        if path == "/servers/run":
            return self.do_vm_run(form, user, ip)
        if path == "/terminal/unlock":
            if not self.lan_direct():
                return self.back("/terminal", "Terminal hanya bisa dibuka dari jaringan sekolah.", True)
            now = time.time()
            recent = [t for t in FAILS.get(ip, []) if now - t < FAIL_WINDOW]
            FAILS[ip] = recent
            if len(recent) >= FAIL_LIMIT:
                return self.back("/terminal", "Terlalu banyak percobaan gagal. Coba lagi 10 menit lagi.", True)
            if not check_password(form.get("p", ""), CFG["users"][user]["hash"]):
                FAILS[ip].append(now)
                write_log(user, "terminal-gagal", "-", ip)
                time.sleep(1)
                return self.back("/terminal", "Password salah.", True)
            TERM_UNLOCK[tok_hash(tok)] = now + TERM_UNLOCK_TTL
            write_log(user, "terminal-buka-kunci", "-", ip)
            return self.redirect("/terminal")
        if path == "/devices/agent-update":
            dev = next((d for d in CFG["devices"] if d["id"] == form.get("id")), None)
            if not dev or not dev.get("agent_secret"):
                return self.back("/settings", "Komputer ini belum dipasangi agen.", True)
            if dev["id"] in SCAN_BUSY:
                return self.back("/settings", "Komputer ini sedang diproses, coba sebentar lagi.", True)
            SCAN_BUSY.add(dev["id"])
            try:
                ok, msg = agent_update(dev, user)
            finally:
                SCAN_BUSY.discard(dev["id"])
            return self.back("/settings", msg, not ok)
        if path == "/apps/uninstall":
            return self.do_apps_uninstall(form, user, ip)
        if path == "/apps/dismiss":
            return self.do_apps_dismiss(form, user, ip)
        with CFG_LOCK:
            if path == "/servers/add":
                return self.do_vm_add(form, user, ip)
            if path == "/servers/delete":
                return self.do_vm_delete(form, user, ip)
            if path == "/servers/install":
                return self.do_vm_install(form, user, ip)
            if path == "/servers/interval":
                return self.do_vm_interval(form, user, ip)
            if path == "/servers/terminal":
                return self.do_vm_terminal_toggle(form, user, ip)
            if path == "/apps/rules/add":
                return self.do_rule_add(form, user, ip)
            if path == "/apps/rules/toggle":
                return self.do_rule_toggle(form, user, ip)
            if path == "/apps/rules/delete":
                return self.do_rule_delete(form, user, ip)
            if path == "/apps/interval":
                return self.do_scan_interval(form, user, ip)
            if path == "/devices/save":
                return self.do_device_save(form, user, ip)
            if path == "/devices/delete":
                return self.do_device_delete(form, user, ip)
            if path == "/devices/agent":
                return self.do_agent(form, user, ip)
            if path == "/devices/agent-remove":
                return self.do_agent_remove(form, user, ip)
            if path == "/users/save":
                return self.do_user_save(form, user, ip)
            if path == "/users/delete":
                return self.do_user_delete(form, user, ip)
            if path == "/settings/general":
                return self.do_general(form, user, ip)
        self._send(404, "Tidak ditemukan")

    def do_login(self, form, ip):
        now = time.time()
        recent = [t for t in FAILS.get(ip, []) if now - t < FAIL_WINDOW]
        FAILS[ip] = recent
        if len(recent) >= FAIL_LIMIT:
            return self._send(429, login_page("Terlalu banyak percobaan gagal. Coba lagi 10 menit lagi."))
        u, p = form.get("u", ""), form.get("p", "")
        rec = CFG["users"].get(u)
        if rec and check_password(p, rec["hash"]):
            FAILS.pop(ip, None)
            write_log(u, "login", "-", ip)
            return self.redirect("/", [self.cookie_header(make_session(u), int(CFG.get("session_hours", 12)) * 3600)])
        FAILS[ip].append(now)
        time.sleep(1)
        return self._send(401, login_page("Nama pengguna atau password salah."))

    def do_wake(self, form, user, ip):
        dev = next((d for d in CFG.get("devices", []) if d["id"] == form.get("id")), None)
        if not dev:
            return self.back("/", "Komputer tidak dikenal.", True)
        if time.time() - WAKE_COOLDOWN.get(dev["id"], 0) < 10:
            return self.back("/", "Perintah baru saja dikirim, tunggu sebentar.", waking=dev["id"])
        try:
            send_wol(dev)
        except Exception as e:
            return self.back("/", f"Gagal mengirim: {e}", True)
        WAKE_COOLDOWN[dev["id"]] = time.time()
        write_log(user, "nyalakan", dev["id"], ip)
        return self.back("/", f"Perintah menyalakan dikirim ke {dev['name']}.", waking=dev["id"])

    def do_shutdown(self, form, user, ip):
        dev = next((d for d in CFG.get("devices", []) if d["id"] == form.get("id")), None)
        if not dev or not dev.get("agent_secret") or not dev.get("ip"):
            return self.back("/", "Komputer ini belum dipasangi agen Matikan.", True)
        key = "stop:" + dev["id"]
        if time.time() - WAKE_COOLDOWN.get(key, 0) < 10:
            return self.back("/", "Perintah baru saja dikirim, tunggu sebentar.", stopping=dev["id"])
        try:
            agent_shutdown(dev, user)
        except Exception as e:
            return self.back("/", f"Gagal mematikan {dev['name']}: {agent_error(e)}.", True)
        WAKE_COOLDOWN[key] = time.time()
        write_log(user, "matikan", dev["id"], ip)
        return self.back("/", f"{dev['name']} akan mati dalam {SHUTDOWN_DELAY} detik.", stopping=dev["id"])

    # ---------------- server / VM
    def do_vm_add(self, form, user, ip):
        name, host = form.get("name", "").strip(), form.get("host", "").strip()
        orig = form.get("orig", "")
        keep = {"f_name": name, "f_host": host, "f_port": form.get("port", "22"), **({"edit": orig} if orig else {})}
        try:
            port = int(form.get("port") or 22)
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            return self.back("/servers", "Port SSH harus angka 1–65535.", True, **keep)
        if not name or len(name) > 60 or not re.fullmatch(r"[A-Za-z0-9.-]{1,100}", host):
            return self.back("/servers", "Isi nama dan IP/host VM yang valid.", True, **keep)
        if orig:
            vm = next((v for v in CFG["vms"] if v["id"] == orig), None)
            if not vm:
                return self.back("/servers", "VM tidak ditemukan.", True)
            if vm_job_running(vm["id"]):
                return self.back("/servers", "Tunggu proses di VM ini selesai dulu.", True, **keep)
            moved = (vm["host"], int(vm.get("port", 22))) != (host, port)
            vm.update(name=name, host=host, port=port)
            save_config(CFG)
            write_log(user, "ubah-vm", vm["id"], ip)
            return self.back("/servers", f"{name} disimpan." + (" Klik Cek untuk memastikan panel bisa menjangkau alamat barunya." if moved else ""))
        vid = slugify(name)
        base, i = vid, 2
        while any(v["id"] == vid for v in CFG["vms"]):
            vid, i = f"{base}-{i}", i + 1
        CFG["vms"].append({"id": vid, "name": name, "host": host, "port": port, "user": "root"})
        save_config(CFG)
        write_log(user, "tambah-vm", vid, ip)
        self.redirect("/servers?" + urlencode({"install": vid, "tok": new_vm_token(vid)}) + "#install")

    def do_vm_install(self, form, user, ip):
        vm = next((v for v in CFG["vms"] if v["id"] == form.get("id")), None)
        if not vm:
            return self.back("/servers", "VM tidak ditemukan.", True)
        if not os.path.exists(VM_TEMPLATE):
            return self.back("/servers", "File vm-update.sh tidak ada di server — jalankan ulang install.sh.", True)
        try:
            ensure_ssh_key()
        except Exception as e:
            return self.back("/servers", f"Gagal membuat kunci SSH panel: {e}. Pastikan openssh-client terpasang (jalankan ulang install.sh).", True)
        self.redirect("/servers?" + urlencode({"install": vm["id"], "tok": new_vm_token(vm["id"])}) + "#install")

    def do_vm_delete(self, form, user, ip):
        vm = next((v for v in CFG["vms"] if v["id"] == form.get("id")), None)
        if not vm:
            return self.back("/servers", "VM tidak ditemukan.", True)
        if vm_job_running(vm["id"]):
            return self.back("/servers", "Tunggu proses di VM ini selesai dulu.", True)
        CFG["vms"] = [v for v in CFG["vms"] if v["id"] != vm["id"]]
        save_config(CFG)
        with VM_LOCK:
            VMSTATE.pop(vm["id"], None)
            save_vmstate()
        write_log(user, "hapus-vm", vm["id"], ip)
        return self.back("/servers", f"{vm['name']} dihapus dari panel.")

    def do_vm_interval(self, form, user, ip):
        try:
            h = float(form.get("hours") or 0)
            if not 0 <= h <= 168:
                raise ValueError
        except ValueError:
            return self.back("/servers", "Isi 0–168 jam.", True)
        CFG["vm_check_hours"] = int(h) if h == int(h) else h
        save_config(CFG)
        return self.back("/servers", "Cek otomatis dimatikan." if h == 0 else f"VM dicek otomatis setiap {CFG['vm_check_hours']} jam.")

    def do_vm_check(self, form, user, ip):
        if form.get("id") == "semua":
            threading.Thread(target=check_all_vms, kwargs={"only_due": False}, daemon=True).start()
            return self.back("/servers", "Pengecekan semua VM berjalan di latar belakang. Muat ulang halaman ini dalam 1 menit.")
        vm = next((v for v in CFG["vms"] if v["id"] == form.get("id")), None)
        if not vm:
            return self.back("/servers", "VM tidak ditemukan.", True)
        if vm_job_running(vm["id"]):
            return self.back("/servers", "Sedang ada proses di VM ini.", True)
        try:
            ensure_ssh_key()
        except Exception as e:
            return self.back("/servers", f"Gagal membuat kunci SSH panel: {e}", True)
        err = vm_check(vm, user)
        if err:
            return self.back("/servers", f"{vm['name']}: {err}", True)
        d = VMSTATE[vm["id"]].get("data", {})
        parts = [f"{d.get('upgradable', 0)} pembaruan OS"]
        if d.get("app"):
            parts.append(f"{d.get('app_behind', '?')} commit baru")
        return self.back("/servers", f"{vm['name']} dicek: " + ", ".join(parts) + ".")

    def lan_direct(self):
        """True bila permintaan datang langsung dari jaringan lokal (bukan lewat reverse proxy / internet)."""
        if any(self.headers.get(h) for h in ("X-Forwarded-For", "X-Real-IP", "Forwarded", "X-Forwarded-Host")):
            return False
        try:
            a = ipaddress.ip_address(self.client_address[0])
        except ValueError:
            return False
        return a.is_private or a.is_loopback

    def term_session(self, user, tok, sid):
        if not user or not is_admin(user) or not self.lan_direct() or not term_unlocked(tok):
            return None
        t = TERMS.get(sid)
        return t if t and t.owner == tok_hash(tok) else None

    def do_terminal_api(self, path, raw, form, user, tok):
        if not user or not is_admin(user):
            return self._send(401, '{"error":"login"}', "application/json")
        if not hmac.compare_digest(self.headers.get("X-CSRF", ""), csrf_for(tok)):
            return self._send(403, '{"error":"csrf"}', "application/json")
        if not self.lan_direct():
            return self._send(403, '{"error":"Terminal hanya dari jaringan sekolah."}', "application/json")
        if not term_unlocked(tok):
            return self._send(403, '{"error":"Ketik ulang password (muat ulang halaman)."}', "application/json")
        q = parse_qs(urlparse(self.path).query)
        if path == "/terminal/open":
            vm = next((v for v in CFG["vms"] if v["id"] == form.get("vm") and v.get("terminal")), None)
            if not vm:
                return self._send(200, json.dumps({"error": "VM ini belum diizinkan terminal."}), "application/json")
            try:
                ensure_term_key()
                t = TermSession(vm, user, tok)
                t.resize(int(form.get("rows") or 30), int(form.get("cols") or 100))
            except Exception as e:
                return self._send(200, json.dumps({"error": f"Gagal membuka SSH: {e}"}), "application/json")
            with TERMS_LOCK:
                TERMS[t.id] = t
            write_log(user, "terminal", f"{vm['id']}:{vm['name']}", self.client_ip())
            return self._send(200, json.dumps({"sid": t.id}), "application/json")
        sid = q.get("sid", [""])[0] or form.get("sid", "")
        t = self.term_session(user, tok, sid)
        if not t:
            return self._send(403, '{"error":"sesi"}', "application/json")
        if path == "/terminal/in":
            t.write(raw[:65536])
        elif path == "/terminal/resize":
            try:
                t.resize(int(form.get("rows") or 30), int(form.get("cols") or 100))
            except ValueError:
                pass
        elif path == "/terminal/close":
            t.last = time.time()
            t.close()
        else:
            return self._send(404, "{}", "application/json")
        return self._send(200, '{"ok":true}', "application/json")

    def do_vm_terminal_toggle(self, form, user, ip):
        vm = next((v for v in CFG["vms"] if v["id"] == form.get("id")), None)
        if not vm:
            return self.back("/servers", "VM tidak ditemukan.", True)
        vm["terminal"] = not vm.get("terminal")
        if vm["terminal"]:
            try:
                ensure_term_key()
            except Exception as e:
                vm["terminal"] = False
                return self.back("/servers", f"Gagal membuat kunci terminal: {e}", True)
        else:  # tutup sesi yang masih terbuka ke VM ini
            for t in list(TERMS.values()):
                if t.vm["id"] == vm["id"]:
                    t.close()
        save_config(CFG)
        write_log(user, "terminal-izin" if vm["terminal"] else "terminal-cabut", f"{vm['id']}:{vm['name']}", ip)
        self.redirect("/servers?" + urlencode({"install": vm["id"], "tok": new_vm_token(vm["id"]),
                                               "msg": ("Terminal diizinkan di panel. " if vm["terminal"] else "Izin terminal dicabut di panel. ")
                                               + "Jalankan perintah di bawah pada VM itu agar kuncinya ikut diperbarui."}) + "#install")

    def do_vm_run(self, form, user, ip):
        vm = next((v for v in CFG["vms"] if v["id"] == form.get("id")), None)
        action = form.get("action", "")
        if not vm or action not in ("os-upgrade", "app-update", "reboot", "self-update"):
            return self.back("/servers", "Permintaan tidak valid.", True)
        if vm_job_running(vm["id"]):
            return self.back("/servers", "Sedang ada proses di VM ini.", True)
        run_vm_job(vm, action, user)
        return self.redirect(f"/servers#vm-{quote(vm['id'])}")

    # ---------------- aplikasi
    def apps_back(self, form, msg, err=False):
        dev = form.get("back") or form.get("dev_back") or ""
        return self.back("/apps", msg, err, **({"dev": dev} if dev else {}))

    def do_apps_scan(self, form, user, ip):
        target = form.get("dev", "")
        if target == "semua":
            write_log(user, "pindai", "semua", ip)
            threading.Thread(target=scan_all, args=(user,), daemon=True).start()
            return self.back("/apps", "Pemindaian semua komputer berjalan di latar belakang. Muat ulang halaman ini dalam 1–2 menit.")
        dev = next((d for d in CFG["devices"] if d["id"] == target), None)
        if not dev or not dev.get("agent_secret"):
            return self.apps_back(form, "Komputer ini belum dipasangi agen.", True)
        write_log(user, "pindai", dev["id"], ip)
        msg = scan_device(dev, user)
        err = bool((SCANS.get(dev["id"]) or {}).get("error"))
        return self.apps_back(form, msg, err)

    def do_apps_uninstall(self, form, user, ip):
        dev = next((d for d in CFG["devices"] if d["id"] == form.get("dev")), None)
        app_id = form.get("app", "")
        app = next((a for a in (SCANS.get(dev["id"]) or {}).get("apps", []) if a.get("id") == app_id), None) if dev else None
        home = form.get("back") == "home"
        back = {"dev": form["back"]} if form.get("back") and not home else {}
        dest = "/" if home else "/apps"
        if not dev or not dev.get("agent_secret") or not app:
            return self.back(dest, "Aplikasi tidak ditemukan. Pindai ulang komputer ini.", True, **back)
        if dev["id"] in SCAN_BUSY:
            return self.back(dest, "Komputer ini sedang diproses, coba sebentar lagi.", True, **back)
        SCAN_BUSY.add(dev["id"])
        try:
            ok, msg = uninstall_app(dev, app_id, user)
        finally:
            SCAN_BUSY.discard(dev["id"])
        return self.back(dest, msg, not ok, **back)

    def do_apps_dismiss(self, form, user, ip):
        dev_id, app_id = form.get("dev", ""), form.get("app", "")
        with SCAN_LOCK:
            sd = SCANS.get(dev_id)
            f = (sd or {}).get("failed", {}).pop(app_id, None)
            if sd is not None and app_id not in sd.setdefault("dismissed", []):
                sd["dismissed"].append(app_id)
            save_scans()
        name = (f or {}).get("name", "Aplikasi")
        return self.back("/", f"{name} diabaikan dan tidak akan dihapus otomatis lagi di komputer ini.")

    def do_rule_add(self, form, user, ip):
        pattern = form.get("pattern", "").strip()
        literal = re.sub(r"[*?\s]", "", pattern)
        back = {"dev": form["dev"]} if form.get("dev") else {}
        if len(literal) < 3 or len(pattern) > 80:
            return self.back("/apps", "Aturan minimal 3 huruf (selain tanda *).", True, **back)
        if any(r["pattern"].lower() == pattern.lower() for r in CFG["app_rules"]):
            return self.back("/apps", f"Aturan '{pattern}' sudah ada.", True, **back)
        auto = form.get("mode") == "auto"
        CFG["app_rules"].append({"id": secrets.token_hex(4), "pattern": pattern, "auto": auto})
        save_config(CFG)
        write_log(user, "aturan-aplikasi", pattern, ip)
        if auto:
            threading.Thread(target=self.auto_now, daemon=True).start()
        msg = f"Aturan '{pattern}' ditambahkan" + (" — aplikasi yang cocok dihapus di latar belakang." if auto else ".")
        return self.back("/apps", msg, **back)

    @staticmethod
    def auto_now():
        for d in list(CFG["devices"]):
            if d.get("agent_secret") and d.get("ip") and d["id"] in SCANS and d["id"] not in SCAN_BUSY and agent_ping(d)[0]:
                SCAN_BUSY.add(d["id"])
                try:
                    run_auto_rules(d)
                finally:
                    SCAN_BUSY.discard(d["id"])

    def do_rule_toggle(self, form, user, ip):
        r = next((r for r in CFG["app_rules"] if r["id"] == form.get("rid")), None)
        if not r:
            return self.back("/apps", "Aturan tidak ditemukan.", True)
        r["auto"] = not r.get("auto")
        save_config(CFG)
        write_log(user, "aturan-aplikasi", r["pattern"], ip)
        if r["auto"]:
            threading.Thread(target=self.auto_now, daemon=True).start()
        return self.back("/apps", f"Aturan '{r['pattern']}' sekarang " + ("hapus otomatis." if r["auto"] else "hanya dilaporkan."))

    def do_rule_delete(self, form, user, ip):
        r = next((r for r in CFG["app_rules"] if r["id"] == form.get("rid")), None)
        if not r:
            return self.back("/apps", "Aturan tidak ditemukan.", True)
        CFG["app_rules"] = [x for x in CFG["app_rules"] if x["id"] != r["id"]]
        save_config(CFG)
        write_log(user, "aturan-aplikasi", r["pattern"], ip)
        return self.back("/apps", f"Aturan '{r['pattern']}' dihapus.")

    def do_scan_interval(self, form, user, ip):
        try:
            m = int(form.get("minutes") or 0)
            if not 0 <= m <= 1440:
                raise ValueError
        except ValueError:
            return self.back("/apps", "Isi 0–1440 menit.", True)
        CFG["scan_minutes"] = m
        save_config(CFG)
        return self.back("/apps", "Pemindaian otomatis dimatikan." if m == 0 else f"Komputer dipindai otomatis setiap {m} menit saat menyala.")

    def do_agent(self, form, user, ip):
        dev = next((d for d in CFG["devices"] if d["id"] == form.get("id")), None)
        if not dev:
            return self.back("/settings", "Komputer tidak ditemukan.", True)
        if not dev.get("ip"):
            return self.back("/settings", "Isi dulu IP komputer (Ubah) sebelum memasang agen.", True)
        if not os.path.exists(AGENT_TEMPLATE):
            return self.back("/settings", "File windows-agent.ps1 tidak ada di server — jalankan ulang install.sh.", True)
        if not dev.get("agent_secret"):
            dev["agent_secret"] = secrets.token_hex(32)
            dev.setdefault("agent_port", AGENT_PORT)
        dev.pop("agent_version", None)  # dicek ulang setelah dipasang
        save_config(CFG)
        write_log(user, "token-agen", dev["id"], ip)
        self.redirect("/settings?" + urlencode({"agent": dev["id"], "tok": new_agent_token(dev["id"])}) + "#agent")

    def do_agent_remove(self, form, user, ip):
        dev = next((d for d in CFG["devices"] if d["id"] == form.get("id")), None)
        if not dev:
            return self.back("/settings", "Komputer tidak ditemukan.", True)
        dev.pop("agent_secret", None)
        dev.pop("agent_port", None)
        dev.pop("agent_version", None)
        for t, (did, _) in list(AGENT_TOKENS.items()):
            if did == dev["id"]:
                AGENT_TOKENS.pop(t, None)
        save_config(CFG)
        write_log(user, "lepas-agen", dev["id"], ip)
        return self.back("/settings", f"Agen dilepas dari {dev['name']}. Untuk menghapus dari Windows, lihat README.")

    def do_account(self, form, user, ip):
        rec = CFG["users"][user]
        if not check_password(form.get("old", ""), rec["hash"]):
            return self.back("/account", "Password lama salah.", True)
        p1, p2 = form.get("p1", ""), form.get("p2", "")
        if len(p1) < 8 or p1 != p2:
            return self.back("/account", "Password baru minimal 8 karakter dan harus sama di kedua kolom.", True)
        with CFG_LOCK:
            rec["hash"] = hash_password(p1)
            rec["sv"] = rec.get("sv", 0) + 1
            save_config(CFG)
        write_log(user, "ganti-password", user, ip)
        # sesi lama tidak berlaku lagi -> beri sesi baru untuk perangkat ini
        return self.redirect("/account?" + urlencode({"msg": "Password berhasil diganti."}),
                             [self.cookie_header(make_session(user), int(CFG.get("session_hours", 12)) * 3600)])

    def do_device_save(self, form, user, ip):
        orig = form.get("orig", "")
        others = [d for d in CFG["devices"] if d["id"] != orig]
        dev, err = build_device(form, others)
        if err:
            keep = {f"f_{k}": form.get(k, "") for k in ("name", "id", "mac", "ip", "broadcast", "port", "check_ports", "remote_url")}
            if orig:
                keep["edit"] = orig
            return self.back("/settings", err, True, **keep)
        old = next((d for d in CFG["devices"] if d["id"] == orig), None) if orig else None
        if old:
            for k in ("agent_secret", "agent_port"):  # kunci agen tetap dipakai saat data komputer diubah
                if k in old:
                    dev[k] = old[k]
            if old["id"] != dev["id"]:
                for t, (did, exp) in list(AGENT_TOKENS.items()):
                    if did == old["id"]:
                        AGENT_TOKENS[t] = (dev["id"], exp)
            CFG["devices"] = [dev if d["id"] == orig else d for d in CFG["devices"]]
            msg = f"{dev['name']} berhasil diperbarui."
        else:
            CFG["devices"].append(dev)
            msg = f"{dev['name']} berhasil ditambahkan."
        save_config(CFG)
        write_log(user, "simpan-perangkat", dev["id"], ip)
        return self.back("/settings", msg)

    def do_device_delete(self, form, user, ip):
        did = form.get("id", "")
        dev = next((d for d in CFG["devices"] if d["id"] == did), None)
        if not dev:
            return self.back("/settings", "Komputer tidak ditemukan.", True)
        CFG["devices"] = [d for d in CFG["devices"] if d["id"] != did]
        save_config(CFG)
        write_log(user, "hapus-perangkat", did, ip)
        return self.back("/settings", f"{dev['name']} dihapus.")

    def do_user_save(self, form, user, ip):
        u = form.get("u", "").strip()
        role = "admin" if form.get("role") == "admin" else "user"
        p1, p2 = form.get("p1", ""), form.get("p2", "")
        if not USER_RE.match(u):
            return self.back("/settings", "Nama pengguna 3–32 karakter: huruf, angka, titik, minus, garis bawah.", True, f_u=u, tab="pengguna")
        if len(p1) < 8 or p1 != p2:
            return self.back("/settings", "Password minimal 8 karakter dan harus sama di kedua kolom.", True, f_u=u, tab="pengguna")
        rec = CFG["users"].get(u)
        if rec and rec.get("role") == "admin" and role != "admin" and admin_count() <= 1:
            return self.back("/settings", "Harus ada minimal satu admin.", True, f_u=u, tab="pengguna")
        existed = rec is not None
        CFG["users"][u] = {"hash": hash_password(p1), "role": role, "sv": (rec or {}).get("sv", 0) + (1 if existed else 0)}
        save_config(CFG)
        write_log(user, "simpan-pengguna", u, ip)
        if u == user:  # mengubah akun sendiri -> perbarui sesi
            return self.redirect("/settings?" + urlencode({"msg": "Akun Anda diperbarui.", "tab": "pengguna"}),
                                 [self.cookie_header(make_session(u), int(CFG.get("session_hours", 12)) * 3600)])
        return self.back("/settings", f"Pengguna {u} {'diperbarui' if existed else 'ditambahkan'}.", tab="pengguna")

    def do_user_delete(self, form, user, ip):
        u = form.get("u", "")
        if u == user:
            return self.back("/settings", "Tidak bisa menghapus akun sendiri.", True, tab="pengguna")
        rec = CFG["users"].get(u)
        if not rec:
            return self.back("/settings", "Pengguna tidak ditemukan.", True, tab="pengguna")
        if rec.get("role") == "admin" and admin_count() <= 1:
            return self.back("/settings", "Harus ada minimal satu admin.", True, tab="pengguna")
        del CFG["users"][u]
        save_config(CFG)
        write_log(user, "hapus-pengguna", u, ip)
        return self.back("/settings", f"Pengguna {u} dihapus.", tab="pengguna")

    def do_general(self, form, user, ip):
        try:
            hours = int(form.get("session_hours") or 12)
            if not 1 <= hours <= 720:
                raise ValueError
        except ValueError:
            return self.back("/settings", "Lama sesi harus 1–720 jam.", True, tab="umum")
        CFG["trust_proxy"] = form.get("trust_proxy") == "1"
        CFG["session_hours"] = hours
        save_config(CFG)
        write_log(user, "pengaturan-umum", "-", ip)
        return self.back("/settings", "Pengaturan umum disimpan.", tab="umum")


# -------------------------------------------------------------------- CLI
def ask(prompt, default=""):
    v = input(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
    return v or default


def ask_password():
    while True:
        p1 = getpass.getpass("Password (min. 8 karakter): ")
        if len(p1) < 8:
            print("Terlalu pendek.")
            continue
        if p1 != getpass.getpass("Ulangi password: "):
            print("Tidak sama.")
            continue
        return p1


def cmd_init():
    if os.path.exists(CONFIG_PATH):
        print(f"{CONFIG_PATH} sudah ada, dilewati.")
        return
    user = ask("Nama pengguna admin", "admin")
    cfg = {"listen": "0.0.0.0", "port": 8080, "trust_proxy": False, "session_hours": 12,
           "secret": secrets.token_hex(32),
           "users": {user: {"hash": hash_password(ask_password()), "role": "admin", "sv": 0}},
           "devices": []}
    save_config(cfg)
    print("Akun admin dibuat. Tambahkan komputer lewat menu Pengaturan di web.")


def cmd_resetpw(name):
    cfg = load_config()
    rec = cfg["users"].get(name, {"role": "admin", "sv": 0})
    rec["hash"] = hash_password(ask_password())
    rec["sv"] = rec.get("sv", 0) + 1
    cfg["users"][name] = rec
    save_config(cfg)
    print(f"Password '{name}' disimpan (peran: {rec.get('role')}). Semua sesi login akun ini otomatis keluar.")
    print("Jalankan: systemctl restart wol-panel")


def main():
    global CFG
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if cmd == "init":
        return cmd_init()
    if not os.path.exists(CONFIG_PATH):
        sys.exit("config.json belum ada. Jalankan dulu: python3 wol.py init")
    CFG = load_config()
    if cmd == "users":
        for u, v in sorted(CFG["users"].items()):
            print(f"{u:<24} {v.get('role', 'user')}")
        return
    if cmd == "resetpw":
        if len(sys.argv) < 3:
            sys.exit("Pakai: python3 wol.py resetpw <nama_pengguna>")
        return cmd_resetpw(sys.argv[2])
    if cmd == "list":
        st = all_status()
        for d in CFG["devices"]:
            s = {True: "menyala", False: "mati", None: "-"}[st[d["id"]]]
            print(f"{d['id']:<16} {d['name']:<22} {d['mac']}  {d.get('ip', ''):<15} {s}")
        return
    if cmd == "wake":
        if len(sys.argv) < 3:
            sys.exit("Pakai: python3 wol.py wake <id>")
        dev = next((d for d in CFG["devices"] if d["id"] == sys.argv[2]), None)
        if not dev:
            sys.exit("ID tidak ditemukan. Lihat: python3 wol.py list")
        send_wol(dev)
        write_log("cli", "nyalakan", dev["id"], "localhost")
        print(f"Magic packet dikirim ke {dev['mac']} via {dev.get('broadcast')}.")
        return
    if cmd == "serve":
        addr = (CFG.get("listen", "0.0.0.0"), int(CFG.get("port", 8080)))
        print(f"WOL Panel berjalan di http://{addr[0]}:{addr[1]}")
        load_scans()
        load_vmstate()
        threading.Thread(target=term_reaper, daemon=True).start()
        threading.Thread(target=scanner_loop, daemon=True).start()
        ThreadingHTTPServer(addr, Handler).serve_forever()
        return
    print(__doc__)


if __name__ == "__main__":
    main()
