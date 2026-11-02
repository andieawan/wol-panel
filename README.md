# WOL Panel

Panel web ringan untuk menghidupkan komputer desktop lewat Wake-on-LAN (WOL).
Berjalan di server (container LXC kecil di Proxmox sudah cukup), satu file Python, tanpa database.

Alurnya: **buka panel → klik Hidupkan → tunggu status "Menyala" (30–90 detik) → klik Buka Remote.**

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
  Setiap komputer punya tombol **Buka Remote** di Beranda; bawaannya membuka Chrome Remote Desktop
  (remotedesktop.google.com/access), linknya bisa diganti per komputer.
- **Pengguna**: tambah akun, reset password, hapus. Ada dua peran:
  - *Admin*: bisa menyalakan komputer dan mengubah pengaturan.
  - *Pengguna*: hanya bisa menyalakan dan mematikan komputer.
- **Umum**: mode reverse proxy (NPMplus) dan lama sesi login.

Setiap akun bisa mengganti passwordnya sendiri di menu **Akun**. Riwayat login, perintah menyalakan,
dan perubahan pengaturan tampil di Beranda untuk admin.

Jika lupa password admin, jalankan di server:

```bash
cd /opt/wol-panel
python3 wol.py users                 # lihat nama akun yang ada
python3 wol.py resetpw andi          # ganti 'andi' dengan nama akun admin Anda
systemctl restart wol-panel
```

### Mematikan komputer dari panel

WOL hanya bisa menyalakan. Untuk tombol **Matikan**, komputer Windows perlu dipasangi agen kecil
(script PowerShell bawaan Windows, tanpa instalasi program lain):

1. Di panel: **Pengaturan**, lalu klik **Agen** pada komputer tujuan. Panel menampilkan satu baris perintah.
2. Di komputer tujuan: klik kanan Start → **Terminal (Admin)**, tempel perintah tersebut, lalu Enter.
3. Kalau muncul tulisan hijau *Berhasil*, klik **Tes** di panel. Hasil yang diharapkan: *Agen Matikan: aktif*.

Setelah itu tombol **Matikan** muncul di Beranda. Komputer menampilkan peringatan dan mati 10 detik kemudian.
Perintahnya berlaku 15 menit; kalau kedaluwarsa, klik **Agen** lagi.

Keamanan agen:
- Berjalan sebagai layanan Windows (Scheduled Task SYSTEM) di port 8765.
- Firewall Windows hanya membuka port itu untuk IP panel.
- Setiap perintah ditandatangani kunci rahasia, berlaku 2 menit, dan tidak bisa diulang.
- Kunci disimpan di `C:\ProgramData\WOLPanelAgent`, yang hanya bisa dibaca Administrator.
- Log agen ada di `C:\ProgramData\WOLPanelAgent\agent.log`.

Menghapus agen dari Windows (PowerShell Admin):

```powershell
Unregister-ScheduledTask -TaskName 'WOL Panel Agent' -Confirm:$false
Unregister-ScheduledTask -TaskName 'WOL Panel Agent Restart' -Confirm:$false
Remove-NetFirewallRule -DisplayName 'WOL Panel Agent'
Remove-Item "$env:ProgramData\WOLPanelAgent" -Recurse -Force
```

Lalu di panel klik **Agen** → **Lepas agen**.

### Pembaruan agen

Mulai agen versi 4, agen bisa **diperbarui dari panel dengan satu tombol**, jadi tidak perlu dipasang ulang di setiap
komputer.
1. Setelah server panel di-update (`git pull && bash install.sh`), panel mengecek versi agen di setiap komputer yang
   menyala, setiap menit.
2. Komputer dengan agen lebih lama diberi tanda *ada versi X* di **Pengaturan → Komputer**, dan tombol
   **Perbarui agen** muncul.
3. Saat tombol diklik, panel mengirim kode agen terbaru. Kode itu ditandatangani kunci rahasia, jadi hanya panel Anda
   yang bisa memperbarui.
4. Agen memeriksa kode baru, menyimpan cadangan, lalu memulai ulang dirinya. Kalau agen baru gagal berjalan, versi
   lama dipulihkan otomatis.

Pembaruan **tidak berjalan sendiri**; agen hanya diperbarui saat tombolnya diklik.

Agen versi 1–3 belum punya kemampuan ini, sehingga perlu **dipasang ulang sekali** (tombol **Pasang ulang**).
Panel menandainya dengan *pasang ulang sekali*.

### Pemindai aplikasi (menu Aplikasi)

Agen yang sama juga memindai aplikasi yang terpasang di komputer. Yang dibaca:
- aplikasi untuk semua pengguna,
- aplikasi di profil setiap akun, termasuk game yang terpasang tanpa hak admin seperti Roblox,
- aplikasi Microsoft Store.

Cara pakai:
1. Buka menu **Aplikasi**, lalu tambahkan **aturan** berupa nama aplikasi, misalnya `roblox` atau `Google Play Games`.
   Tanpa tanda `*` berarti "nama mengandung".
2. Pilih tindakan untuk aturan itu:
   - **Laporkan saja**: aplikasi ditandai di bagian *Cocok dengan aturan*, lalu Anda klik **Uninstall** sendiri.
   - **Hapus otomatis**: aplikasi langsung di-uninstall setiap kali komputer dipindai.
3. Komputer yang menyala dipindai otomatis setiap 60 menit (bisa diubah, 0 = mati). Bisa juga dipindai kapan saja
   lewat **Pindai** atau **Pindai semua sekarang**.
4. **Lihat aplikasi** menampilkan semua aplikasi di satu komputer dalam tiga kelompok:
   - **Dari luar**: dipasang dari installer di luar Store. Label **Dipasang sendiri** berarti terpasang di satu
     akun tanpa hak admin, biasanya dipasang sendiri oleh siswa.
   - **Store**: dipasang dari Microsoft Store oleh pengguna.
   - **Bawaan**: ikut Windows atau pabrikan, misalnya aplikasi sistem, driver, dan runtime.

   Pencarian berlaku untuk semua kelompok. Di setiap baris ada tombol **Uninstall** dan **Jadikan aturan**.
5. Aplikasi yang **gagal dihapus**, baik otomatis maupun manual, muncul di Beranda pada kartu **Perlu ditangani manual**:
   - **Coba lagi**: menjalankan uninstall sekali lagi.
   - **Abaikan**: menyembunyikan item itu dan tidak lagi menghapusnya otomatis di komputer tersebut.

   Item hilang sendiri setelah aplikasinya tidak terdeteksi lagi pada pemindaian berikutnya.

Cara uninstall yang dipakai agen:
- Memakai uninstaller senyap bila tersedia (MSI, Inno Setup, atau *QuietUninstallString*).
- Untuk aplikasi di profil siswa (mis. Roblox), proses dihentikan, lalu folder aplikasi dan shortcut-nya dihapus.
- Aplikasi Store dihapus untuk semua pengguna.
- Kalau sebuah aplikasi tidak bisa dihapus otomatis, panel memberi tahu agar di-uninstall manual. Penghapusan
  otomatis yang gagal tidak diulang selama 6 jam.

Aplikasi sistem (Windows, driver, .NET, Visual C++, Office, Edge, Chrome Remote Desktop, dan WOL Panel)
**tidak pernah dihapus otomatis** walaupun cocok dengan aturan. Aplikasi itu tetap bisa di-uninstall manual.

> Agen yang dipasang sebelum fitur ini ada perlu dipasang ulang: **Pengaturan → Agen**, lalu jalankan
> perintahnya lagi di komputer tersebut. Panel memberi tanda *Agen versi lama* bila belum.

### Update VM aplikasi (menu Server)

Menu **Server** dipakai untuk memperbarui VM aplikasi (Pusat, Absensi, BK, TU, PKL, Website, Jurnal). Ada dua jenis update:
- **Update OS**: `apt-get upgrade`.
- **Update aplikasi**: menjalankan `deploy/update.sh` milik aplikasi itu, yang berisi backup database, mode pemeliharaan,
  `git pull`, `composer`, `migrate --force`, cache, dan reload PHP-FPM.

Cara menyambungkan VM:
1. **Server → Tambah VM**: isi nama dan IP VM. Panel menampilkan satu perintah.
2. Di konsol VM (Proxmox → Console), masuk sebagai root, tempel perintah itu, lalu Enter.
3. Klik **Cek** pada VM tersebut.

Panel mengecek otomatis setiap 6 jam (bisa diubah). Yang ditampilkan:
- jumlah paket OS yang bisa di-update, termasuk berapa yang update keamanan,
- commit baru di repo aplikasi,
- apakah VM perlu reboot.

Update **tidak pernah berjalan sendiri**; Anda yang klik tombolnya, lalu log prosesnya tampil langsung di panel.

Keamanan:
- Di VM dipasang `/usr/local/sbin/wol-update`.
- Kunci SSH panel di `/root/.ssh/authorized_keys` dikunci dengan `restrict`, `from="IP panel"`, dan
  `command="/usr/local/sbin/wol-update"`. Panel hanya bisa menjalankan `check`, `os-upgrade`, `app-update`, dan
  `reboot`, tanpa shell bebas.
- Folder aplikasi dideteksi dari `/var/www/*/deploy/update.sh` dan bisa diubah di `/etc/wol-update.conf`.

**Memperbarui WOL Panel sendiri dari menu Server:** tambahkan container panel sebagai VM (IP container itu sendiri),
lalu jalankan perintah pasangnya di container tersebut. Repo panel di `/root/wol-panel` terdeteksi otomatis, dan
**Update aplikasi** menjalankan `deploy/update.sh` milik panel (`git pull` + `install.sh`). Layanan panel dimulai
ulang 5 detik setelah update selesai, jadi halaman cukup dimuat ulang. Perintah yang sama bisa dijalankan manual:
`cd ~/wol-panel && bash deploy/update.sh`.

**Memperbarui skrip `wol-update` di VM:** kalau panel punya versi lebih baru, kartu VM menampilkan
*wol-update vX · ada vY* dan tombol **Perbarui wol-update**. VM mengunduh skrip itu sendiri dari repo resmi
(`WOL_UPDATE_SRC`, bawaan `andieawan/wol-panel` branch `main`). Panel tidak mengirim kode, jadi kunci SSH panel tetap
tidak bisa dipakai untuk menjalankan perintah lain. Skrip yang rusak atau versinya lebih lama ditolak. `wol-update`
versi 1–2 belum punya kemampuan ini, jadi perlu **Lainnya → Pasang ulang** sekali.

Mencabut akses panel dari sebuah VM:

```bash
sed -i '/wol-panel-update$/d' /root/.ssh/authorized_keys
rm -f /usr/local/sbin/wol-update /etc/wol-update.conf
```

### Terminal web (menu Terminal)

Terminal web adalah shell root ke VM langsung dari browser, jadi tidak perlu PuTTY. Karena aksesnya sangat besar,
terminal dibatasi ketat:
- **Hanya admin.**
- **Hanya dari jaringan sekolah.** Terminal ditolak bila panel dibuka lewat NPMplus/internet; buka panel langsung
  di `http://IP-container:8080`.
- **Wajib mengetik ulang password** setiap 30 menit.
- **Izin per VM.** Di **Server**, klik **Izinkan terminal**, lalu jalankan perintah pasang yang muncul di VM itu.
  Kunci terminal terpisah dari kunci update dan hanya diterima dari IP panel.
- **Semua tampilan sesi direkam** di `/opt/wol-panel/vmlogs/terminal/`.
- **Ditutup otomatis** setelah 30 menit tanpa aktivitas.

Untuk mencabut izin, klik **Cabut terminal** di Server, lalu jalankan perintah pasang yang muncul di VM itu.
Kunci terminalnya akan dihapus dari VM.

Komponen tampilan terminal memakai [xterm.js](https://xtermjs.org) (lisensi MIT, lihat `static/XTERM-LICENSE.txt`).
Komponen ini disimpan di panel, jadi tidak memerlukan internet.

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
| Tombol Matikan gagal: *agen tidak merespons* | Agen belum terpasang, atau Windows belum selesai booting. Klik **Tes** untuk detail |
| Tombol Matikan gagal: *menolak IP panel* / *kunci tidak cocok* | IP panel berubah atau kunci diganti — klik **Agen** lalu jalankan ulang perintahnya di komputer tujuan |
| Status "Menyala" padahal komputer sedang Sleep | Kartu jaringan Intel dengan *ARP Offload* tetap menjawab ARP saat Sleep. Tombol Hidupkan tetap bisa dipakai |

Status dicek berurutan: port (misalnya 3389), lalu ARP, lalu ping. ARP tetap dijawab Windows walau ping
diblokir firewall, tapi hanya berfungsi jika server dan komputer berada di jaringan (subnet) yang sama.

**Desktop beda VLAN/subnet dengan server** (misalnya desktop di jaringan lab/kantor yang dipisah MikroTik):
paket broadcast tidak menyeberang router. Solusinya pasang interface tambahan container di VLAN desktop,
atau kirim langsung dari MikroTik: `/tool wol mac=AA:BB:CC:DD:EE:FF interface=bridge-lab`.

## Keamanan bawaan
Password disimpan ter-hash (PBKDF2), sesi ditandatangani (otomatis batal saat password diganti), peran admin/pengguna, proteksi CSRF pada tombol,
login diblokir 10 menit setelah 5 kali salah, dan setiap login/perintah menyalakan dicatat di `wol.log`.
