#!/usr/bin/env python3
"""
WOL Panel - panel web ringan untuk menghidupkan komputer lewat Wake-on-LAN.
Hanya memakai pustaka standar Python 3 (tanpa pip install).

Perintah:
  python3 wol.py init                 buat config.json + akun admin pertama
  python3 wol.py adduser              tambah / ganti password pengguna
  python3 wol.py adddevice            tambah komputer yang akan dihidupkan
  python3 wol.py list                 tampilkan daftar komputer + status
  python3 wol.py wake <id>            kirim magic packet dari terminal
  python3 wol.py serve                jalankan panel web
"""
import base64
import getpass
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("WOL_CONFIG", os.path.join(BASE, "config.json"))
LOG_PATH = os.environ.get("WOL_LOG", os.path.join(BASE, "wol.log"))
COOKIE = "wol_session"
CFG = {}
LOG_LOCK = threading.Lock()
FAILS = {}  # ip -> [timestamps] percobaan login gagal
FAIL_LIMIT, FAIL_WINDOW = 5, 600
WAKE_COOLDOWN = {}  # device id -> waktu terakhir dikirim


# ---------------------------------------------------------------- konfigurasi
def load_config():
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return json.load(f)


def save_config(cfg):
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    os.chmod(tmp, 0o600)
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


# ------------------------------------------------------------- wake-on-lan
def magic_packet(mac):
    return b"\xff" * 6 + bytes.fromhex(normalize_mac(mac).replace(":", "")) * 16


def send_wol(dev):
    pkt = magic_packet(dev["mac"])
    target = dev.get("broadcast") or "255.255.255.255"
    ports = [int(dev.get("port", 9))]
    if ports[0] == 9:
        ports.append(7)  # sebagian kartu jaringan hanya mendengar port 7
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for _ in range(3):
            for p in ports:
                s.sendto(pkt, (target, p))
            time.sleep(0.1)


def is_online(dev):
    ip = dev.get("ip")
    if not ip:
        return None
    for p in dev.get("check_ports", [3389]):
        try:
            socket.create_connection((ip, int(p)), timeout=0.8).close()
            return True
        except OSError:
            pass
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        return r.returncode == 0
    except Exception:
        return False


def all_status():
    devs = CFG.get("devices", [])
    with ThreadPoolExecutor(max_workers=max(1, min(16, len(devs)))) as ex:
        res = list(ex.map(is_online, devs))
    return {d["id"]: r for d, r in zip(devs, res)}


def write_log(user, dev_id, ip, note="wake"):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')}\t{user}\t{note}\t{dev_id}\t{ip}\n"
    with LOG_LOCK, open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line)


def read_log(n=15):
    try:
        with open(LOG_PATH, encoding="utf-8") as f:
            lines = f.readlines()[-n:]
    except FileNotFoundError:
        return []
    return [l.rstrip("\n").split("\t") for l in reversed(lines)]


# ------------------------------------------------------------------ sesi
def _sign(data):
    return hmac.new(CFG["secret"].encode(), data.encode(), hashlib.sha256).hexdigest()


def make_session(user):
    exp = int(time.time() + CFG.get("session_hours", 12) * 3600)
    raw = f"{user}|{exp}|{secrets.token_hex(8)}"
    return base64.urlsafe_b64encode(f"{raw}|{_sign(raw)}".encode()).decode()


def verify_session(token):
    try:
        user, exp, nonce, sig = base64.urlsafe_b64decode(token.encode()).decode().split("|")
        raw = f"{user}|{exp}|{nonce}"
        if hmac.compare_digest(sig, _sign(raw)) and int(exp) > time.time() and user in CFG["users"]:
            return user
    except Exception:
        pass
    return None


def csrf_for(token):
    return _sign("csrf|" + token)[:32]


# ------------------------------------------------------------------ HTML
CSS = """
:root{--bg:#f4f6f8;--card:#fff;--fg:#1d2733;--mut:#6b7785;--line:#e3e8ee;--acc:#1f6feb;--ok:#1a7f37;--off:#8c959f;--warn:#bf8700;--err:#cf222e}
@media (prefers-color-scheme:dark){:root{--bg:#0f141a;--card:#171e26;--fg:#e6edf3;--mut:#8b98a5;--line:#2a333d;--acc:#4493f8;--ok:#3fb950;--off:#6e7681;--warn:#d29922;--err:#f85149}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:720px;margin:0 auto;padding:20px 16px 40px}
header{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
h1{font-size:20px;margin:0}.mut{color:var(--mut);font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:12px}
.dev{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap}
.dev h2{font-size:16px;margin:0 0 2px}
.badge{display:inline-flex;align-items:center;gap:6px;font-size:13px;font-weight:600}
.dot{width:9px;height:9px;border-radius:50%;background:var(--off)}
.on .dot{background:var(--ok)}.on{color:var(--ok)}.off{color:var(--off)}.wait .dot{background:var(--warn)}.wait{color:var(--warn)}
button{font:inherit;border:0;border-radius:8px;padding:9px 16px;cursor:pointer;background:var(--acc);color:#fff;font-weight:600}
button:disabled{opacity:.5;cursor:default}button.ghost{background:transparent;color:var(--mut);border:1px solid var(--line);padding:6px 12px}
.msg{padding:10px 14px;border-radius:8px;margin-bottom:12px;border:1px solid var(--line);background:var(--card)}
.msg.err{border-color:var(--err);color:var(--err)}
input{font:inherit;width:100%;padding:9px 12px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--fg);margin:4px 0 12px}
table{width:100%;border-collapse:collapse;font-size:13px}td{padding:6px 4px;border-top:1px solid var(--line)}
.login{max-width:360px;margin:12vh auto}
"""

JS = """
const fmt={true:['on','Menyala'],false:['off','Mati'],null:['off','Tidak dicek']};
async function refresh(){
  try{
    const r=await fetch('/api/status',{cache:'no-store'});
    if(r.status===401){location='/login';return}
    const s=await r.json();
    for(const [id,v] of Object.entries(s)){
      const b=document.getElementById('st-'+id); if(!b) continue;
      const waking=b.dataset.waking==='1' && v!==true;
      const [cls,txt]=waking?['wait','Sedang dihidupkan…']:fmt[v];
      b.className='badge '+cls; b.lastElementChild.textContent=txt;
      if(v===true) b.dataset.waking='0';
      const btn=document.getElementById('btn-'+id); if(btn) btn.disabled=(v===true);
    }
  }catch(e){}
}
refresh(); setInterval(refresh,5000);
"""


def page(title, body, script=""):
    return f"""<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title>
<style>{CSS}</style></head><body><div class="wrap">{body}</div>{f'<script>{script}</script>' if script else ''}</body></html>"""


def login_page(err=""):
    e = f'<div class="msg err">{html.escape(err)}</div>' if err else ""
    return page("Masuk – WOL Panel", f"""<div class="login card"><h1>WOL Panel</h1>
<p class="mut">Masuk untuk menghidupkan komputer.</p>{e}
<form method="post" action="/login"><label>Nama pengguna<input name="u" autocomplete="username" required autofocus></label>
<label>Password<input name="p" type="password" autocomplete="current-password" required></label>
<button style="width:100%">Masuk</button></form></div>""")


def main_page(user, token, msg="", waking=""):
    csrf = csrf_for(token)
    m = f'<div class="msg">{html.escape(msg)}</div>' if msg else ""
    cards = []
    for d in CFG.get("devices", []):
        did = html.escape(d["id"])
        w = "1" if d["id"] == waking else "0"
        cards.append(f"""<div class="card dev"><div><h2>{html.escape(d.get('name', d['id']))}</h2>
<div class="mut">{html.escape(d.get('ip', '-'))} · {html.escape(normalize_mac(d['mac']))}</div>
<span id="st-{did}" class="badge off" data-waking="{w}"><span class="dot"></span><span>Mengecek…</span></span></div>
<form method="post" action="/wake"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="id" value="{did}">
<button id="btn-{did}">Hidupkan</button></form></div>""")
    if not cards:
        cards.append('<div class="card mut">Belum ada komputer. Tambahkan dengan <code>python3 wol.py adddevice</code>.</div>')
    rows = "".join(f"<tr><td>{html.escape(r[0])}</td><td>{html.escape(r[1])}</td><td>{html.escape(r[3])}</td><td class='mut'>{html.escape(r[4])}</td></tr>"
                   for r in read_log() if len(r) >= 5)
    log = f'<div class="card"><b>Riwayat</b><table>{rows}</table></div>' if rows else ""
    return page("WOL Panel", f"""<header><div><h1>WOL Panel</h1><div class="mut">Masuk sebagai {html.escape(user)}</div></div>
<form method="post" action="/logout"><input type="hidden" name="csrf" value="{csrf}"><button class="ghost">Keluar</button></form></header>
{m}{''.join(cards)}{log}<p class="mut">Status diperbarui otomatis tiap 5 detik. Komputer biasanya butuh 30–90 detik sampai siap di-remote.</p>""", JS)


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
                         "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
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

    def cookie_header(self, value, max_age):
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "").lower() == "https" else ""
        return ("Set-Cookie", f"{COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}")

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/login":
            return self._send(200, login_page())
        user, tok = self.session()
        if not user:
            if url.path.startswith("/api/"):
                return self._send(401, '{"error":"login"}', "application/json")
            return self.redirect("/login")
        if url.path == "/":
            q = parse_qs(url.query)
            return self._send(200, main_page(user, tok, q.get("msg", [""])[0], q.get("waking", [""])[0]))
        if url.path == "/api/status":
            return self._send(200, json.dumps(all_status()), "application/json")
        self._send(404, page("Tidak ditemukan", "<p>Halaman tidak ditemukan.</p>"))

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 10_000:
            return self._send(413, "Terlalu besar")
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode("utf-8", "replace")).items()}
        path = urlparse(self.path).path
        ip = self.client_ip()

        if path == "/login":
            now = time.time()
            recent = [t for t in FAILS.get(ip, []) if now - t < FAIL_WINDOW]
            FAILS[ip] = recent
            if len(recent) >= FAIL_LIMIT:
                return self._send(429, login_page("Terlalu banyak percobaan gagal. Coba lagi 10 menit lagi."))
            u, p = form.get("u", ""), form.get("p", "")
            stored = CFG["users"].get(u)
            if stored and check_password(p, stored):
                FAILS.pop(ip, None)
                write_log(u, "-", ip, "login")
                return self.redirect("/", [self.cookie_header(make_session(u), CFG.get("session_hours", 12) * 3600)])
            FAILS[ip].append(now)
            time.sleep(1)
            return self._send(401, login_page("Nama pengguna atau password salah."))

        user, tok = self.session()
        if not user:
            return self.redirect("/login")
        if not hmac.compare_digest(form.get("csrf", ""), csrf_for(tok)):
            return self._send(403, page("Ditolak", "<p>Sesi kedaluwarsa, silakan muat ulang halaman.</p>"))

        if path == "/logout":
            return self.redirect("/login", [self.cookie_header("", 0)])

        if path == "/wake":
            dev = next((d for d in CFG.get("devices", []) if d["id"] == form.get("id")), None)
            if not dev:
                return self.redirect("/?msg=" + quote("Komputer tidak dikenal."))
            last = WAKE_COOLDOWN.get(dev["id"], 0)
            if time.time() - last < 10:
                return self.redirect("/?msg=" + quote("Perintah baru saja dikirim, tunggu sebentar.") + "&waking=" + quote(dev["id"]))
            try:
                send_wol(dev)
            except Exception as e:
                return self.redirect("/?msg=" + quote(f"Gagal mengirim: {e}"))
            WAKE_COOLDOWN[dev["id"]] = time.time()
            write_log(user, dev["id"], ip)
            msg = f"Perintah menyalakan dikirim ke {dev.get('name', dev['id'])}."
            return self.redirect("/?msg=" + quote(msg) + "&waking=" + quote(dev["id"]))

        self._send(404, "Tidak ditemukan")


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
        sys.exit(f"{CONFIG_PATH} sudah ada. Pakai 'adduser' / 'adddevice'.")
    user = ask("Nama pengguna admin", "admin")
    cfg = {"listen": "0.0.0.0", "port": 8080, "trust_proxy": False, "session_hours": 12,
           "secret": secrets.token_hex(32), "users": {user: hash_password(ask_password())}, "devices": []}
    save_config(cfg)
    print(f"Tersimpan di {CONFIG_PATH}. Lanjutkan dengan: python3 wol.py adddevice")


def cmd_adduser():
    cfg = load_config()
    user = ask("Nama pengguna")
    cfg["users"][user] = hash_password(ask_password())
    save_config(cfg)
    print("Tersimpan.")


def cmd_adddevice():
    cfg = load_config()
    name = ask("Nama komputer", "Desktop")
    did = ask("ID singkat (huruf kecil, tanpa spasi)", re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-"))
    mac = normalize_mac(ask("MAC address (contoh 3C:7C:3F:12:34:56)"))
    ip = ask("IP komputer (untuk cek status, boleh kosong)")
    bc = ""
    if ip:
        bc = str(ipaddress.ip_network(f"{ip}/24", strict=False).broadcast_address)
    bc = ask("Alamat broadcast jaringan", bc or "255.255.255.255")
    ports = ask("Port untuk cek status (pisahkan koma; 3389=RDP, 22=SSH)", "3389")
    cfg["devices"] = [d for d in cfg["devices"] if d["id"] != did]
    cfg["devices"].append({"id": did, "name": name, "mac": mac, "ip": ip, "broadcast": bc, "port": 9,
                           "check_ports": [int(p) for p in ports.split(",") if p.strip().isdigit()]})
    save_config(cfg)
    print(f"Komputer '{name}' ditambahkan (id: {did}).")


def main():
    global CFG
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if cmd == "init":
        return cmd_init()
    if not os.path.exists(CONFIG_PATH):
        sys.exit("config.json belum ada. Jalankan dulu: python3 wol.py init")
    CFG = load_config()
    if cmd == "adduser":
        return cmd_adduser()
    if cmd == "adddevice":
        return cmd_adddevice()
    if cmd == "list":
        st = all_status()
        for d in CFG["devices"]:
            s = {True: "menyala", False: "mati", None: "-"}[st[d["id"]]]
            print(f"{d['id']:<15} {d.get('name', ''):<20} {d['mac']}  {d.get('ip', ''):<15} {s}")
        return
    if cmd == "wake":
        if len(sys.argv) < 3:
            sys.exit("Pakai: python3 wol.py wake <id>")
        dev = next((d for d in CFG["devices"] if d["id"] == sys.argv[2]), None)
        if not dev:
            sys.exit("ID tidak ditemukan. Lihat: python3 wol.py list")
        send_wol(dev)
        write_log("cli", dev["id"], "localhost")
        print(f"Magic packet dikirim ke {dev['mac']} via {dev.get('broadcast')}.")
        return
    if cmd == "serve":
        addr = (CFG.get("listen", "0.0.0.0"), int(CFG.get("port", 8080)))
        print(f"WOL Panel berjalan di http://{addr[0]}:{addr[1]}")
        ThreadingHTTPServer(addr, Handler).serve_forever()
        return
    print(__doc__)


if __name__ == "__main__":
    main()
