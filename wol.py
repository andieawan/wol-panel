#!/usr/bin/env python3
"""
WOL Panel - panel web ringan untuk menghidupkan komputer lewat Wake-on-LAN.
Hanya memakai pustaka standar Python 3 (tanpa pip install).

Semua pengaturan (perangkat, pengguna, pengaturan umum) dikelola dari web,
menu "Pengaturan" (khusus peran admin).

Perintah terminal:
  python3 wol.py init              buat config.json + akun admin pertama
  python3 wol.py resetpw <nama>    reset password / buat admin jika lupa password
  python3 wol.py list              tampilkan daftar komputer + status
  python3 wol.py wake <id>         kirim magic packet dari terminal
  python3 wol.py serve             jalankan panel web
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
import shutil
import socket
import subprocess
import sys
import threading
import time
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


# ---------------------------------------------------------------- konfigurasi
def migrate(cfg):
    """Menyesuaikan config versi lama (password berupa string) ke format baru."""
    for u, v in list(cfg.get("users", {}).items()):
        if isinstance(v, str):
            cfg["users"][u] = {"hash": v, "role": "admin", "sv": 0}
    cfg.setdefault("devices", [])
    cfg.setdefault("trust_proxy", False)
    cfg.setdefault("session_hours", 12)
    return cfg


def load_config():
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return migrate(json.load(f))


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
    return f"Tes {dev['name']} ({ip}) — " + " · ".join(out)


def all_status():
    devs = list(CFG.get("devices", []))
    if not devs:
        return {}
    with ThreadPoolExecutor(max_workers=min(16, len(devs))) as ex:
        res = list(ex.map(is_online, devs))
    return {d["id"]: r for d, r in zip(devs, res)}


def write_log(user, action, target, ip):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')}\t{user}\t{action}\t{target}\t{ip}\n"
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
    return {"id": did, "name": name, "mac": mac, "ip": ip, "broadcast": bc,
            "port": port, "check_ports": checks}, None


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
:root{--bg:#f4f6f8;--card:#fff;--fg:#1d2733;--mut:#6b7785;--line:#e3e8ee;--acc:#1f6feb;--ok:#1a7f37;--off:#8c959f;--warn:#bf8700;--err:#cf222e}
@media (prefers-color-scheme:dark){:root{--bg:#0f141a;--card:#171e26;--fg:#e6edf3;--mut:#8b98a5;--line:#2a333d;--acc:#4493f8;--ok:#3fb950;--off:#6e7681;--warn:#d29922;--err:#f85149}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:760px;margin:0 auto;padding:20px 16px 40px}
header{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:18px}
h1{font-size:20px;margin:0}h2{font-size:16px;margin:0 0 10px}.mut{color:var(--mut);font-size:13px}
nav{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
nav a{color:var(--mut);text-decoration:none;padding:6px 10px;border-radius:8px}nav a.on{color:var(--fg);background:var(--card);border:1px solid var(--line)}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:12px}
.dev{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap}
.dev h2{margin:0 0 2px}
.badge{display:inline-flex;align-items:center;gap:6px;font-size:13px;font-weight:600}
.dot{width:9px;height:9px;border-radius:50%;background:var(--off)}
.on .dot{background:var(--ok)}.badge.on{color:var(--ok)}.badge.off{color:var(--off)}.wait .dot{background:var(--warn)}.wait{color:var(--warn)}
button,.btn{font:inherit;border:0;border-radius:8px;padding:9px 16px;cursor:pointer;background:var(--acc);color:#fff;font-weight:600;text-decoration:none;display:inline-block}
button:disabled{opacity:.5;cursor:default}
button.ghost,.btn.ghost{background:transparent;color:var(--mut);border:1px solid var(--line);padding:6px 12px;font-weight:500}
button.danger{background:transparent;color:var(--err);border:1px solid var(--line);padding:6px 12px;font-weight:500}
.msg{padding:10px 14px;border-radius:8px;margin-bottom:12px;border:1px solid var(--ok);background:var(--card)}
.msg.err{border-color:var(--err);color:var(--err)}
label{display:block;font-size:13px;color:var(--mut)}
input,select{font:inherit;width:100%;padding:9px 12px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--fg);margin:4px 0 12px}
input[type=checkbox]{width:auto;margin:0 8px 0 0;vertical-align:middle}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:0 12px}@media(max-width:560px){.grid{grid-template-columns:1fr}}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{padding:8px 4px;border-top:1px solid var(--line);text-align:left;vertical-align:middle}
th{font-size:12px;color:var(--mut);font-weight:600;border-top:0}
.acts{display:flex;gap:6px;justify-content:flex-end;flex-wrap:wrap}.acts form{margin:0}
.tbl{overflow-x:auto}.login{max-width:360px;margin:12vh auto}code{font-size:13px}
"""

JS_STATUS = """
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
    }
  }catch(e){}
}
refresh(); setInterval(refresh,5000);
"""


def page(title, body, script=""):
    return f"""<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{E(title)}</title>
<style>{CSS}</style></head><body><div class="wrap">{body}</div>{f'<script>{script}</script>' if script else ''}</body></html>"""


def shell(user, csrf, active, content, q, script=""):
    links = [("/", "Beranda")]
    if is_admin(user):
        links.append(("/settings", "Pengaturan"))
    links.append(("/account", "Akun"))
    nav = "".join(f'<a href="{h}" class="{"on" if h == active else ""}">{t}</a>' for h, t in links)
    msg = q.get("msg", [""])[0]
    m = f'<div class="msg{" err" if q.get("err") else ""}">{E(msg)}</div>' if msg else ""
    return page("WOL Panel", f"""<header><div><h1>WOL Panel</h1><div class="mut">Masuk sebagai {E(user)}
({'admin' if is_admin(user) else 'pengguna'})</div></div><nav>{nav}
<form method="post" action="/logout" style="margin:0"><input type="hidden" name="csrf" value="{csrf}">
<button class="ghost">Keluar</button></form></nav></header>{m}{content}""", script)


def hidden(csrf, **kw):
    return f'<input type="hidden" name="csrf" value="{csrf}">' + "".join(
        f'<input type="hidden" name="{k}" value="{E(str(v))}">' for k, v in kw.items())


def confirm(text):
    # json.dumps -> string JS yang aman, lalu di-escape untuk atribut HTML
    return 'onsubmit="return confirm(' + E(json.dumps(text)) + ')"'


def del_form(action, csrf, text, **fields):
    return (f'<form method="post" action="{action}" {confirm(text)}>'
            f'{hidden(csrf, **fields)}<button class="danger">Hapus</button></form>')


def login_page(err=""):
    e = f'<div class="msg err">{E(err)}</div>' if err else ""
    return page("Masuk – WOL Panel", f"""<div class="login card"><h1>WOL Panel</h1>
<p class="mut">Masuk untuk menghidupkan komputer.</p>{e}
<form method="post" action="/login"><label>Nama pengguna<input name="u" autocomplete="username" required autofocus></label>
<label>Password<input name="p" type="password" autocomplete="current-password" required></label>
<button style="width:100%">Masuk</button></form></div>""")


def home_page(user, csrf, q):
    waking = q.get("waking", [""])[0]
    cards = []
    for d in CFG.get("devices", []):
        did = E(d["id"])
        cards.append(f"""<div class="card dev"><div><h2>{E(d['name'])}</h2>
<div class="mut">{E(d.get('ip') or '-')} · {E(d['mac'])}</div>
<span id="st-{did}" class="badge off" data-waking="{'1' if d['id'] == waking else '0'}"><span class="dot"></span><span>Mengecek…</span></span></div>
<form method="post" action="/wake">{hidden(csrf, id=d['id'])}<button id="btn-{did}">Hidupkan</button></form></div>""")
    if not cards:
        tip = 'Tambahkan lewat menu <a href="/settings">Pengaturan</a>.' if is_admin(user) else "Hubungi admin untuk menambahkan."
        cards.append(f'<div class="card mut">Belum ada komputer. {tip}</div>')
    rows = "".join(f"<tr><td>{E(r[0])}</td><td>{E(r[1])}</td><td>{E(r[2])}</td><td>{E(r[3])}</td><td class='mut'>{E(r[4])}</td></tr>"
                   for r in read_log() if len(r) >= 5)
    log = f'<div class="card"><h2>Riwayat</h2><div class="tbl"><table>{rows}</table></div></div>' if rows and is_admin(user) else ""
    body = "".join(cards) + log + '<p class="mut">Status diperbarui otomatis tiap 5 detik. Komputer biasanya butuh 30–90 detik sampai siap di-remote.</p>'
    return shell(user, csrf, "/", body, q, JS_STATUS)


def settings_page(user, csrf, q):
    edit_id = q.get("edit", [""])[0]
    ed = next((d for d in CFG["devices"] if d["id"] == edit_id), None)
    # isian form dikembalikan saat ada error
    f = {k: v[0] for k, v in q.items() if k.startswith("f_")}
    val = lambda k, dflt="": E(f.get("f_" + k, dflt))

    rows = []
    for d in CFG["devices"]:
        dl = (f'<form method="post" action="/devices/test">{hidden(csrf, id=d["id"])}'
              f'<button class="ghost" title="Cek port, ARP, dan ping">Tes</button></form>'
              + del_form("/devices/delete", csrf, f"Hapus {d['name']}?", id=d["id"]))
        rows.append(f"""<tr><td><b>{E(d['name'])}</b><div class="mut">{E(d['id'])}</div></td>
<td><code>{E(d['mac'])}</code></td><td>{E(d.get('ip') or '-')}</td>
<td><div class="acts"><a class="btn ghost" href="/settings?edit={quote(d['id'])}#form-dev">Ubah</a>{dl}</div></td></tr>""")
    rows = "".join(rows) or '<tr><td colspan="4" class="mut">Belum ada komputer.</td></tr>'

    src = ed or {}
    def dv(k, dflt=""):
        if f:
            return val(k, dflt)
        v = src.get(k, dflt)
        return E(", ".join(map(str, v)) if isinstance(v, list) else str(v))

    dev_form = f"""<form method="post" action="/devices/save" id="form-dev">{hidden(csrf, orig=ed['id'] if ed else '')}
<h2>{'Ubah: ' + E(ed['name']) if ed else 'Tambah komputer'}</h2>
<div class="grid">
<label>Nama komputer<input name="name" value="{dv('name')}" required maxlength="60" placeholder="Desktop Kantor"></label>
<label>ID singkat (kosongkan = otomatis)<input name="id" value="{dv('id')}" maxlength="32" placeholder="desktop-kantor"></label>
<label>MAC address<input name="mac" value="{dv('mac')}" required placeholder="3C:7C:3F:12:34:56"></label>
<label>IP komputer (untuk cek status)<input name="ip" value="{dv('ip')}" placeholder="192.168.10.50"></label>
<label>Alamat broadcast (kosongkan = otomatis)<input name="broadcast" value="{dv('broadcast')}" placeholder="192.168.10.255"></label>
<label>Port WOL<input name="port" type="number" min="1" max="65535" value="{dv('port', '9')}"></label>
<label>Port untuk cek status (pisahkan koma)<input name="check_ports" value="{dv('check_ports', '3389')}" placeholder="3389"></label>
</div>
<p class="mut" style="margin-top:0">3389 = Remote Desktop, 22 = SSH (boleh dikosongkan). Status juga dicek lewat ARP dan ping,
jadi tetap terdeteksi walau Remote Desktop tidak aktif. Pakai tombol <b>Tes</b> untuk melihat hasil tiap cara cek.</p>
<button>{'Simpan perubahan' if ed else 'Tambah komputer'}</button>
{'<a class="btn ghost" href="/settings">Batal</a>' if ed else ''}</form>"""

    urows = []
    for u, v in sorted(CFG["users"].items()):
        me = ' <span class="mut">(Anda)</span>' if u == user else ""
        dl = "" if u == user else del_form("/users/delete", csrf, f"Hapus pengguna {u}?", u=u)
        role = "Admin" if v.get("role") == "admin" else "Pengguna"
        urows.append(f'<tr><td><b>{E(u)}</b>{me}</td><td>{role}</td><td><div class="acts">{dl}</div></td></tr>')
    urows = "".join(urows)

    user_form = f"""<form method="post" action="/users/save">{hidden(csrf)}
<h2>Tambah pengguna / reset password</h2>
<p class="mut" style="margin-top:0">Jika nama pengguna sudah ada, password dan perannya akan diganti.</p>
<div class="grid">
<label>Nama pengguna<input name="u" required pattern="[A-Za-z0-9._\\-]{{3,32}}" value="{val('u')}" autocomplete="off"></label>
<label>Peran<select name="role"><option value="user">Pengguna – hanya bisa menyalakan</option>
<option value="admin">Admin – bisa mengubah pengaturan</option></select></label>
<label>Password (min. 8 karakter)<input name="p1" type="password" minlength="8" required autocomplete="new-password"></label>
<label>Ulangi password<input name="p2" type="password" minlength="8" required autocomplete="new-password"></label>
</div><button>Simpan pengguna</button></form>"""

    general = f"""<form method="post" action="/settings/general">{hidden(csrf)}
<h2>Umum</h2>
<label style="margin-bottom:12px;color:var(--fg)"><input type="checkbox" name="trust_proxy" value="1" {'checked' if CFG.get('trust_proxy') else ''}>
Panel diakses lewat reverse proxy (NPMplus / Nginx)</label>
<p class="mut" style="margin-top:-6px">Centang hanya jika panel dibuka lewat subdomain di NPMplus, agar IP asli pengunjung tercatat dan pembatasan login bekerja benar.</p>
<label>Lama sesi login (jam)<input name="session_hours" type="number" min="1" max="720" value="{int(CFG.get('session_hours', 12))}" style="max-width:160px"></label>
<button>Simpan</button></form>"""

    body = f"""<div class="card"><h2>Komputer</h2><div class="tbl"><table>
<tr><th>Nama</th><th>MAC</th><th>IP</th><th></th></tr>{rows}</table></div></div>
<div class="card">{dev_form}</div>
<div class="card"><h2>Pengguna</h2><div class="tbl"><table><tr><th>Nama</th><th>Peran</th><th></th></tr>{urows}</table></div></div>
<div class="card">{user_form}</div>
<div class="card">{general}</div>"""
    return shell(user, csrf, "/settings", body, q)


def account_page(user, csrf, q):
    body = f"""<div class="card"><form method="post" action="/account">{hidden(csrf)}
<h2>Ganti password</h2>
<label>Password lama<input name="old" type="password" required autocomplete="current-password"></label>
<label>Password baru (min. 8 karakter)<input name="p1" type="password" minlength="8" required autocomplete="new-password"></label>
<label>Ulangi password baru<input name="p2" type="password" minlength="8" required autocomplete="new-password"></label>
<button>Ganti password</button></form>
<p class="mut">Setelah password diganti, sesi login di perangkat lain otomatis keluar.</p></div>"""
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
        self._send(404, page("Tidak ditemukan", '<p>Halaman tidak ditemukan. <a href="/">Kembali</a></p>'))

    # ---------------- POST
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 20_000:
            return self._send(413, "Terlalu besar")
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode("utf-8", "replace"), keep_blank_values=True).items()}
        path = urlparse(self.path).path
        ip = self.client_ip()

        if path == "/login":
            return self.do_login(form, ip)

        user, tok = self.session()
        if not user:
            return self.redirect("/login")
        if not hmac.compare_digest(form.get("csrf", ""), csrf_for(tok)):
            return self._send(403, page("Ditolak", '<p>Sesi kedaluwarsa, silakan <a href="/">muat ulang halaman</a>.</p>'))

        if path == "/logout":
            return self.redirect("/login", [self.cookie_header("", 0)])
        if path == "/wake":
            return self.do_wake(form, user, ip)
        if path == "/account":
            return self.do_account(form, user, ip)

        if not is_admin(user):
            return self._send(403, page("Ditolak", "<p>Hanya admin yang boleh mengubah pengaturan.</p>"))
        if path == "/devices/test":
            dev = next((d for d in CFG["devices"] if d["id"] == form.get("id")), None)
            if not dev:
                return self.back("/settings", "Komputer tidak ditemukan.", True)
            return self.back("/settings", diagnose(dev))
        with CFG_LOCK:
            if path == "/devices/save":
                return self.do_device_save(form, user, ip)
            if path == "/devices/delete":
                return self.do_device_delete(form, user, ip)
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
            keep = {f"f_{k}": form.get(k, "") for k in ("name", "id", "mac", "ip", "broadcast", "port", "check_ports")}
            if orig:
                keep["edit"] = orig
            return self.back("/settings", err, True, **keep)
        if orig and any(d["id"] == orig for d in CFG["devices"]):
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
            return self.back("/settings", "Nama pengguna 3–32 karakter: huruf, angka, titik, minus, garis bawah.", True, f_u=u)
        if len(p1) < 8 or p1 != p2:
            return self.back("/settings", "Password minimal 8 karakter dan harus sama di kedua kolom.", True, f_u=u)
        rec = CFG["users"].get(u)
        if rec and rec.get("role") == "admin" and role != "admin" and admin_count() <= 1:
            return self.back("/settings", "Harus ada minimal satu admin.", True, f_u=u)
        existed = rec is not None
        CFG["users"][u] = {"hash": hash_password(p1), "role": role, "sv": (rec or {}).get("sv", 0) + (1 if existed else 0)}
        save_config(CFG)
        write_log(user, "simpan-pengguna", u, ip)
        if u == user:  # mengubah akun sendiri -> perbarui sesi
            return self.redirect("/settings?" + urlencode({"msg": "Akun Anda diperbarui."}),
                                 [self.cookie_header(make_session(u), int(CFG.get("session_hours", 12)) * 3600)])
        return self.back("/settings", f"Pengguna {u} {'diperbarui' if existed else 'ditambahkan'}.")

    def do_user_delete(self, form, user, ip):
        u = form.get("u", "")
        if u == user:
            return self.back("/settings", "Tidak bisa menghapus akun sendiri.", True)
        rec = CFG["users"].get(u)
        if not rec:
            return self.back("/settings", "Pengguna tidak ditemukan.", True)
        if rec.get("role") == "admin" and admin_count() <= 1:
            return self.back("/settings", "Harus ada minimal satu admin.", True)
        del CFG["users"][u]
        save_config(CFG)
        write_log(user, "hapus-pengguna", u, ip)
        return self.back("/settings", f"Pengguna {u} dihapus.")

    def do_general(self, form, user, ip):
        try:
            hours = int(form.get("session_hours") or 12)
            if not 1 <= hours <= 720:
                raise ValueError
        except ValueError:
            return self.back("/settings", "Lama sesi harus 1–720 jam.", True)
        CFG["trust_proxy"] = form.get("trust_proxy") == "1"
        CFG["session_hours"] = hours
        save_config(CFG)
        write_log(user, "pengaturan-umum", "-", ip)
        return self.back("/settings", "Pengaturan umum disimpan.")


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
    print(f"Password '{name}' disimpan. Jalankan: systemctl restart wol-panel")


def main():
    global CFG
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if cmd == "init":
        return cmd_init()
    if not os.path.exists(CONFIG_PATH):
        sys.exit("config.json belum ada. Jalankan dulu: python3 wol.py init")
    CFG = load_config()
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
        ThreadingHTTPServer(addr, Handler).serve_forever()
        return
    print(__doc__)


if __name__ == "__main__":
    main()
