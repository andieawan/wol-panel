# WOL Panel

Panel web ringan untuk menghidupkan komputer desktop lewat Wake-on-LAN (WOL).
Berjalan di server (container LXC kecil di Proxmox sudah cukup), satu file Python, tanpa database.

Alurnya: **buka panel → klik Hidupkan → tunggu status "Menyala" (30–90 detik) → remote desktop seperti biasa.**

---

## 1. Siapkan komputer desktop (sekali saja)

**BIOS/UEFI**
- Aktifkan *Wake on LAN* / *Power On by PCI-E* / *Resume by LAN* (nama berbeda tiap merk).
- Matikan *ErP*, *EuP*, atau *Deep Sleep* — kalau aktif, kartu jaringan ikut mati total saat PC dimatikan.

**Windows**
1. Device Manager → Network adapters → kartu LAN (kabel, bukan WiFi) → Properties.
   - Tab *Power Management*: centang **Allow this device to wake the computer** dan **Only allow a magic packet to wake the computer**.
   - Tab *Advanced*: **Wake on Magic Packet = Enabled** (jika ada juga *Shutdown Wake-On-Lan = Enabled*).
2. Control Panel → Power Options → *Choose what the power buttons do* → hilangkan centang **Turn on fast startup**.
3. Catat MAC address: buka CMD, `ipconfig /all`, lihat *Physical Address* kartu Ethernet.
4. Buat IP desktop tetap: di MikroTik, IP → DHCP Server → Leases → pilih desktop → **Make Static**.
5. Untuk cek status, aktifkan Remote Desktop (port 3389). Kalau Anda pakai AnyDesk/RustDesk saja, isi port cek dengan port yang terbuka di desktop, atau izinkan ping di Windows Firewall.

Tanda berhasil: setelah PC dimatikan, lampu port LAN di belakang PC tetap menyala.

> WOL hanya lewat **kabel LAN**, tidak lewat WiFi.

## 2. Pasang panel di server

Buat container LXC Debian 12 kecil di Proxmox (1 core, 256 MB RAM, disk 2 GB), network di bridge yang
**satu jaringan dengan desktop**, misalnya IP `192.168.10.20/24`, gateway `192.168.10.254`.

Di container tersebut jalankan:

```bash
apt update && apt install -y git
git clone https://github.com/andieawan/wol-panel.git
cd wol-panel && bash install.sh
```

Untuk memperbarui di kemudian hari (konfigurasi di `/opt/wol-panel/config.json` tidak tertimpa):

```bash
cd wol-panel && git pull && bash install.sh
```

Skrip hanya meminta nama pengguna + password admin. Setelah selesai, buka `http://192.168.10.20:8080`,
masuk sebagai admin, lalu buka menu **Pengaturan**.

## 3. Pengaturan lewat web

Semua diatur dari menu **Pengaturan** (khusus admin), tanpa perlu restart layanan:

- **Komputer**: tambah, ubah, hapus. Isi nama, MAC address, dan IP. Alamat broadcast dan ID dibuat otomatis jika dikosongkan.
- **Pengguna**: tambah akun, reset password, hapus. Ada dua peran:
  - *Admin*: bisa menyalakan komputer dan mengubah pengaturan.
  - *Pengguna*: hanya bisa menyalakan komputer.
- **Umum**: mode reverse proxy (NPMplus) dan lama sesi login.

Setiap akun bisa mengganti passwordnya sendiri di menu **Akun**. Riwayat login, perintah menyalakan,
dan perubahan pengaturan tampil di Beranda untuk admin.

Jika lupa password admin, jalankan di server:

```bash
cd /opt/wol-panel && python3 wol.py resetpw admin && systemctl restart wol-panel
```

## 4. Akses dari luar sekolah

Pilih salah satu:

**A. Lewat subdomain + NPMplus (paling praktis)**
1. Cloudflare: buat record `wol.smkibupakusari.sch.id` → IP publik sekolah.
2. NPMplus: Proxy Host baru → forward ke `192.168.10.20:8080`, aktifkan SSL (Let's Encrypt) + *Force SSL*.
3. Di panel: **Pengaturan → Umum**, centang *Panel diakses lewat reverse proxy*, lalu Simpan.
4. Disarankan tambah lapisan kedua: *Access List* di NPMplus (basic auth atau batasi IP).

**B. Lewat VPN (paling aman)** — WireGuard di MikroTik atau Tailscale. Setelah tersambung VPN,
buka panel dan remote desktop memakai IP lokal seperti di sekolah.

> Jangan membuka port RDP 3389 langsung ke internet. Untuk remote desktop dari luar, pakai VPN atau
> aplikasi seperti AnyDesk/RustDesk.

## 5. Kalau desktop tidak mau menyala

| Gejala | Penyebab umum |
|---|---|
| Lampu LAN mati saat PC off | ErP/Deep Sleep masih aktif di BIOS |
| Bisa bangun dari Sleep, tidak dari Shutdown | Fast Startup masih aktif, atau BIOS tidak mendukung WOL dari S5 |
| Tidak pernah bangun | MAC salah, atau desktop beda jaringan/VLAN dengan server |
| Status selalu "Mati" padahal menyala | Klik **Tes** di Pengaturan. Jika "ARP: tidak ada jawaban", IP salah atau komputer beda jaringan dengan server. Jika arping/ping "tidak diizinkan", jalankan ulang `install.sh` |
| Tes menulis "MAC TIDAK cocok" | IP yang diisi dipakai perangkat lain — cek IP & MAC dengan `ipconfig /all` di komputer tersebut |
| Status "Menyala" padahal komputer sedang Sleep | Kartu jaringan Intel dengan *ARP Offload* tetap menjawab ARP saat Sleep. Tombol Hidupkan tetap bisa dipakai |

Status dicek berurutan: port (misalnya 3389), lalu ARP, lalu ping. ARP tetap dijawab Windows walau ping
diblokir firewall, tapi hanya berfungsi jika server dan komputer berada di jaringan (subnet) yang sama.

**Desktop beda VLAN/subnet dengan server** (misalnya desktop di jaringan lab/kantor yang dipisah MikroTik):
paket broadcast tidak menyeberang router. Solusinya pasang interface tambahan container di VLAN desktop,
atau kirim langsung dari MikroTik: `/tool wol mac=AA:BB:CC:DD:EE:FF interface=bridge-lab`.

## Keamanan bawaan
Password disimpan ter-hash (PBKDF2), sesi ditandatangani (otomatis batal saat password diganti), peran admin/pengguna, proteksi CSRF pada tombol,
login diblokir 10 menit setelah 5 kali salah, dan setiap login/perintah menyalakan dicatat di `wol.log`.
