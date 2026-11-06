# WOL Panel

Panel web ringan untuk menghidupkan komputer desktop lewat Wake-on-LAN (WOL).
Berjalan di server (container LXC kecil di Proxmox sudah cukup), satu file Python, tanpa database.

Alurnya: **buka panel → klik Hidupkan → tunggu status "Menyala" (30–90 detik) → klik Remote.**

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
**satu jaringan dengan desktop**, misalnya IP `192.168.10.28/24` (susunan IP sekolah: `.20`–`.26` VM aplikasi, `.30` Backup Master), gateway `192.168.10.254`.

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

Skrip hanya meminta nama pengguna + password admin. Setelah selesai, buka `http://192.168.10.28:8080`,
masuk sebagai admin, lalu buka menu **Pengaturan**.

## 3. Pengaturan lewat web

Semua diatur dari menu **Pengaturan** (khusus admin), tanpa perlu restart layanan:

- **Komputer desktop** dan **Komputer lab** (dua tab terpisah): tambah, ubah, hapus. Masing-masing punya daftar,
  *Menunggu ditambahkan*, *Tambah lewat skrip* (perintahnya terpisah, jadi komputer langsung masuk tab yang benar),
  *Cari di jaringan*, dan tambah manual. Jenis bisa dipindah lewat **Ubah → Jenis**. Komputer lama otomatis masuk
  *Komputer lab* bila kategorinya mengandung kata "lab". Isi nama, kategori, MAC address, IP, dan subnet (`24` atau `255.255.255.0`). ID dibuat
  otomatis jika dikosongkan. **Kategori** (mis. *Komputer pengguna*, *Komputer lab*, *Lab 2*) menjadi tab di Beranda, jadi
  yang tampil hanya satu kategori setiap kali. Admin juga melihat tab **Server**. Tiap tab menunjukkan jumlah yang
  menyala, mis. *Komputer lab 5/20*, dan tab terakhir yang dibuka diingat. Komputer boleh berada di subnet lain dari panel (lihat *Komputer di subnet lain* di bawah). Cara
  paling cepat: **Tambah lewat skrip** (di bawah).
  Setiap komputer punya tombol **Remote** di Beranda; bawaannya membuka Chrome Remote Desktop
  (remotedesktop.google.com/access), linknya bisa diganti per komputer.
- **Pengguna**: tambah akun, ubah akses, ganti password (boleh dikosongkan saat mengubah), hapus. Ada dua peran:
  - *Admin*: semua komputer, server/VM, terminal, dan pengaturan. **Hanya bisa masuk dari jaringan sekolah atau VPN**
    (buka panel lewat IP langsung, mis. `http://192.168.10.28:8080`).
  - *Pengguna*: hanya menyalakan dan mematikan **komputer yang dicentang admin** (atau *Semua komputer*, termasuk yang
    ditambahkan nanti). Boleh masuk lewat subdomain dari luar sekolah. Komputer lain tidak tampil dan tidak bisa
    dinyalakan walau dicoba lewat alamat langsung. Tampilannya sederhana: satu **tombol power bulat besar** per
    komputer (abu-abu = mati, tekan untuk menghidupkan; hijau = menyala, tekan untuk mematikan; kuning berkedip =
    sedang diproses) dan tombol Buka Remote. Akun pengguna lama tetap mendapat akses ke semua komputer sampai diubah.
- **Umum**: mode reverse proxy (NPMplus), IP reverse proxy, dan lama sesi login.

Setiap akun bisa mengganti passwordnya sendiri di menu **Akun**. Riwayat login, perintah menyalakan,
dan perubahan pengaturan tampil di Beranda untuk admin.

Jika lupa password admin, jalankan di server:

```bash
cd /opt/wol-panel
python3 wol.py users                 # lihat nama akun yang ada
python3 wol.py resetpw andi          # ganti 'andi' dengan nama akun admin Anda
systemctl restart wol-panel
```

### Tambah komputer lewat skrip

Cocok untuk lab yang komputernya banyak. Di **Pengaturan → Komputer → Tambah lewat skrip**, pilih kategorinya
(mis. *Komputer lab*) lalu klik **Buat perintah**,
lalu di tiap komputer client buka **Terminal (Admin)** dan tempel perintahnya:

```powershell
irm http://IP-PANEL:8080/join/<token>.ps1 | iex
```

Skrip itu:
1. mendeteksi nama komputer, IP, subnet, dan MAC kartu jaringan kabel yang dipakai ke panel (bila tersambung lewat
   Wi-Fi, kartu kabel dipakai bila ada);
2. menyalakan pengaturan Wake-on-LAN di Windows: *Wake on Magic Packet*, izin kartu jaringan membangunkan komputer,
   dan mematikan *Fast Startup*;
3. memasang agen (tombol Matikan, pemindai aplikasi, relay WOL);
4. mendaftar ke panel.

Komputer lalu muncul di **Menunggu ditambahkan** (Beranda juga memberi tahu). Klik **Tambahkan** (nama bisa diganti dulu)
atau **Tambahkan semua**. Komputer yang MAC-nya sudah ada di panel cukup **Perbarui**: IP, subnet, dan agennya
diperbarui, sedangkan nama dan pengaturan lainnya tetap.

Perintahnya berlaku 24 jam, bisa dipakai di banyak komputer, dan bisa dicabut kapan saja. Komputer tidak masuk panel
sebelum admin mengklik Tambahkan. Wake-on-LAN di **BIOS** tetap harus diaktifkan manual di tiap komputer.

### Cari komputer beragen di jaringan

**Pengaturan → Komputer → Cari komputer beragen di jaringan.** Panel memindai port agen (8765) di subnet yang diisi
(bawaannya subnet komputer yang sudah ada, maksimal 4096 alamat sekali cari). Komputer harus sedang menyala. Hasilnya:

| Hasil | Tindakan |
|---|---|
| *IP berubah* (mis. dapat IP baru dari DHCP) | **Perbarui IP** — dikenali dari sidik kunci agen, bukan dari IP |
| *Belum di panel* | **Tambahkan** — nama, MAC, IP, subnet dari agen; masuk kategori yang dipilih |
| *Di daftar tunggu* | **Tambahkan** |
| *Kunci agen beda* (komputer ada, agennya dari pemasangan lain) | **Pasang ulang agen** |
| *Agen versi lama* / *menolak IP panel* | Jalankan skrip **Tambah lewat skrip** di komputer itu |

Komputer baru di subnet yang sudah punya **Alamat WOL tambahan** (IP ARP-broadcast di router) otomatis memakai alamat
yang sama. Perkenalan agen (`/hello`) butuh agen versi 6: klik **Perbarui agen** pada komputer lama. Agen hanya
mengirim nama komputer, MAC, IP, subnet, dan sidik kunci (bukan kuncinya), dan hanya ke IP panel.

### IP diperbarui otomatis

Agen versi 10 melapor ke panel (`POST /agent/beat`) saat komputer menyala lalu tiap 5 menit. Bila IP komputer berubah
(DHCP), panel langsung memakai IP baru — status, Matikan, dan pindai tetap jalan tanpa diubah manual. Laporan
ditandatangani kunci agen, hanya diterima dari jaringan sekolah, dan IP yang dilaporkan harus sama dengan IP pengirim.
IP hanya diganti bila laporannya dari kartu jaringan dengan MAC yang terdaftar (bukan Wi-Fi). Pindah subnet ikut
memakai Alamat WOL subnet barunya. Perubahan tercatat di Aktivitas. Tetap disarankan memberi **DHCP static lease** di
router untuk tiap komputer. Komputer lama: klik **Perbarui agen** sekali (selagi IP-nya masih benar).

### Komputer di subnet lain

Panel bisa menyalakan komputer di subnet lain selama masih satu jaringan sekolah (dirutekan router, tanpa NAT di
antaranya), misalnya panel di `192.168.10.x` dan lab di `192.168.20.x/23`. Saat **Hidupkan** diklik, magic packet dikirim:
- ke alamat broadcast subnet komputer itu (dihitung dari IP + subnet);
- **lewat agen**: bila ada komputer lain yang hidup dan beragen (versi 5) di subnet yang sama, panel menyuruh agen itu
  mengirim magic packet dari dalam subnetnya. Cara ini selalu berhasil karena tidak bergantung pada router. Pesan di
  Beranda menyebut agen yang dipakai.

Bila tidak ada komputer lain yang hidup di subnet itu, paket harus diteruskan router. Router (termasuk MikroTik)
biasanya tidak meneruskan broadcast antar subnet. Di MikroTik, buat satu IP yang tidak dipakai di subnet lab
sebagai alamat broadcast:

```
/ip arp add address=192.168.20.254 mac-address=FF:FF:FF:FF:FF:FF interface=<interface/bridge lab>
```

Lalu di panel, **Ubah** komputer → **Pengaturan lanjutan** → **Alamat WOL tambahan**: `192.168.20.254`. Paket yang
dikirim ke IP itu diteruskan MikroTik sebagai broadcast di subnet lab.

Status Menyala/Mati untuk komputer beda subnet tidak bisa memakai ARP (ARP tidak menembus router). Panel memakai
port agen (8765, hanya dibuka untuk IP panel), port cek, dan ping. Jadi pasang agen di komputer itu, atau isi *Port
untuk cek status* (mis. 3389). Pastikan firewall MikroTik (chain forward) mengizinkan IP panel ke subnet itu:
UDP 7 & 9 (WOL), TCP 8765 (agen), dan ICMP, dan tidak ada masquerade/srcnat untuk lalu lintas antar subnet lokal
(agen hanya menerima IP panel).

**Aplikasi yang tidak terdaftar di Windows** (portable, atau dipasang tanpa installer) tetap terdeteksi lewat
pintasannya di Start menu (agen versi 9), dengan label *hanya dari pintasan* dan lokasi file programnya. Bila
programnya ada di folder profil pengguna, Uninstall menghapus foldernya; bila tidak, panel menunjukkan folder yang
perlu dihapus manual.

**Aturan untuk aplikasi per akun.** Aplikasi seperti *Roblox Player for DKV* memuat nama akun. **Jadikan aturan**
otomatis mengganti nama akun dengan `*` (`Roblox Player for *`), jadi aturan berlaku di semua akun dan komputer.
Aturan lama yang terlanjur memuat nama akun diubah otomatis (tercatat di Aktivitas).

### Wallpaper (menu Wallpaper)

1. **Unggah gambar** JPG/PNG (maks. 16 MB, sebaiknya seukuran layar, mis. 1920×1080). Gambar tersimpan di
   `/opt/wol-panel/wallpapers/` sebagai pustaka.
2. **Terapkan wallpaper**: pilih *Bawaan Windows* atau salah satu gambar, pilih tampilan (isi layar, pas, regangkan,
   tengah, ubin, bentang), centang komputernya (per kategori ada *Centang semua*), lalu **Terapkan**. Hasil per
   komputer tampil di *Hasil terakhir*.
3. **Kunci wallpaper** memasang kebijakan Windows agar siswa tidak bisa menggantinya. Terapkan lagi tanpa centang
   *Kunci* (mis. *Bawaan Windows*) untuk membuka kuncinya.

**Penanda wallpaper diganti.** Setiap wallpaper yang berhasil diterapkan dicatat sebagai wallpaper yang disetujui
untuk komputer itu. Panel mengeceknya tiap 10 menit (atau **Cek sekarang**): bila ada profil pengguna yang
wallpapernya berbeda (dibandingkan lewat isi file/SHA-256, bukan nama file), komputer itu muncul di
**Wallpaper tidak sesuai** (siapa yang mengganti, dengan file apa, sedang login atau tidak) dan kartunya di Beranda
diberi tanda merah *wallpaper diganti*. Pilihannya:
- **Kembalikan** (atau **Kembalikan semua**) — pasang ulang wallpaper yang disetujui;
- **Setujui** — terima wallpaper yang sekarang; penanda muncul lagi bila diganti lagi;
- **Kembalikan otomatis** — wallpaper yang diganti langsung dipasang ulang setiap kali dicek.
Butuh agen versi 8. Agar siswa tidak bisa mengganti sama sekali, pakai **Kunci wallpaper**.

Cara kerjanya: tiap komputer mengunduh sendiri gambarnya dari panel (hanya dari jaringan sekolah) dan mengecek
SHA-256-nya, lalu memasangnya untuk semua profil pengguna (termasuk pengguna baru). Pengguna yang sedang login
langsung melihat perubahannya. Butuh agen versi 7: klik **Perbarui agen** pada komputer lama.

### Hidupkan semua (bergantian)

Di Beranda, tiap kategori yang berisi minimal 2 komputer punya tombol **Hidupkan semua**. Komputer yang masih mati
dihidupkan satu per satu dengan jeda (bawaan 10 detik, ubah di **Pengaturan → Umum → Jeda Hidupkan semua**, 2–300 detik)
supaya arus lonjakan saat banyak PSU menyala bersamaan tidak menjatuhkan MCB. Komputer yang sudah menyala dilewati.
Hanya satu penyalaan bergantian yang berjalan pada satu waktu (antar kategori juga tidak bersamaan); tombol **Hentikan**
membatalkan sisa antrean. Kartu komputer yang belum gilirannya tampil *Menunggu giliran…*. Pengguna biasa hanya
menghidupkan komputer yang diizinkan untuknya.

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

Di **Beranda** (admin), kartu komputer yang agennya lama punya tautan **Perbarui agen**, dan tiap kategori punya tombol
**Perbarui agen (n)** untuk memperbarui semua agen lama di kategori itu sekaligus (latar belakang, 4 bersamaan;
komputer yang mati dilewati, hasilnya di Aktivitas).
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

Menu **Server** dipakai untuk memperbarui VM aplikasi sekolah (Pusat, Website, Jurnal, BK, TU, PKL, Tanggungan,
Backup Master, dan WOL Panel sendiri). Di form **Tambah VM** ada *Isi cepat* berisi nama & IP sesuai susunan IP sekolah
(yang sudah ditambahkan tidak muncul lagi). Ada dua jenis update:
- **Update OS**: `apt-get upgrade`.
- **Update aplikasi**: menjalankan `deploy/update.sh` milik aplikasi itu, yang berisi backup database, mode pemeliharaan,
  `git pull`, `composer`, `migrate --force`, cache, dan reload PHP-FPM.

**Update semua** (di samping **Cek semua**) menjalankan semua pembaruan yang ditemukan Cek terakhir sekaligus. Untuk
tiap VM urutannya *Perbarui wol-update → Update OS → Update aplikasi*, hanya yang memang ada pembaruannya, dan
berhenti bila satu langkah gagal. VM-VM berjalan bersamaan; VM WOL Panel sendiri diproses paling akhir karena panel
restart sebentar setelah diupdate. Daftar yang akan dijalankan tampil di jendela konfirmasi.

Ringkasan server juga tampil di **Beranda** (khusus admin): status aktif/tidak terjangkau (dicek tiap 15 detik lewat
port SSH), OS, lama menyala, disk, jumlah pembaruan, perlu reboot, proses yang sedang berjalan, plus tombol **Cek semua**,
**Update semua**, **Terminal**, dan **Kelola**.

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

### Pasang aplikasi di VM baru

VM yang **baru dibuat (≤ 7 hari, dihitung dari waktu OS dipasang) dan belum berisi aplikasi apa pun** (tidak ada folder di
`/var/www` selain `html`) mendapat kotak **Pasang aplikasi** di kartunya. Kotak ini tidak muncul di VM lain.

1. Buat VM (Ubuntu 24.04 + user biasa), lalu **Server → Tambah VM** (*Isi cepat* sesuai susunan IP) dan jalankan perintah
   pasang wol-update di konsol VM. Klik **Cek**.
2. Pilih aplikasinya (yang IP-nya cocok sudah terpilih) → **Pasang aplikasi**. Log berjalan langsung di kartu (±5–10 menit).
3. Sesudah selesai: atur Proxy Host di NPMplus. Pusat & Jurnal: buat admin pertama lewat **Terminal** (perintahnya tertulis
   di akhir log). Website & Backup Master mencetak kredensial admin di log — catat lalu ganti password.

Keamanan: daftar aplikasi, alamat repo GitHub, dan folder tujuan ditulis di `wol-update` (di VM), bukan dikirim panel —
panel hanya memilih kode (`pusat`, `web`, `jurnal`, `bk`, `tu`, `pkl`, `tanggungan`, `backup`). `wol-update` menolak
`app-install` di VM yang sudah berisi aplikasi atau lebih tua dari 7 hari, walau panel memintanya. Domain bawaan
`<subdomain>.smkibupakusari.sch.id` dan batas hari bisa diganti di `/etc/wol-update.conf` (`DOMAIN_BASE`, `FRESH_DAYS`).
Butuh wol-update versi 7.

### Cek aplikasi hidup, status backup, dan notifikasi

**Cek aplikasi.** Selain port SSH, panel memeriksa aplikasinya sendiri lewat `wol-update health` (setiap 5 menit, bisa
diubah di **Pengaturan → Umum**): layanan yang aktif di VM (nginx, PHP-FPM, MariaDB/MySQL, wol-panel) harus *active*,
dan halaman `/up` aplikasi Laravel (alamat dari `APP_URL` di `.env`, diminta langsung ke nginx di VM) harus menjawab 200.
Hasilnya tampil sebagai *Aplikasi OK* atau *Aplikasi bermasalah: …* di menu Server dan Beranda. Setelah **Update OS** atau
**Update aplikasi** selesai, panel langsung mengecek lagi dan menulis hasilnya di akhir log. Butuh wol-update versi 6
(klik **Perbarui wol-update**).

**Status backup dari Backup Master.** Bila panel disambungkan ke Backup Master (**Pengaturan → Umum → Backup Master &
notifikasi**: alamat, mis. `http://192.168.10.30`, dan kunci API `BM_API_KUNCI`), tiap kartu VM menampilkan umur backup
terakhirnya (*Backup 5 jam lalu*, atau tanda ⚠ bila Backup Master melihat masalah), dan jendela konfirmasi **Update
aplikasi** menyebut kapan backup terakhir dibuat. VM dicocokkan lewat IP sumber di Backup Master. Data diambil tiap 10 menit;
hanya ringkasan, bukan isi backup.

**Notifikasi Telegram** lewat bot Backup Master (panel tidak menyimpan token bot). Pilih kejadiannya di pengaturan yang sama:
- VM tidak terjangkau ±3 menit, dan saat kembali terjangkau;
- aplikasi bermasalah (2 kali cek berturut-turut, atau langsung setelah update), dan saat pulih;
- ada update keamanan OS (sekali per jumlah baru);
- update / reboot dari panel gagal.
Tombol **Kirim notifikasi tes** memastikan sambungannya. Di Backup Master isi `BM_TELEGRAM_TOKEN`, `BM_TELEGRAM_CHAT`,
`BM_API_KUNCI`, dan `BM_API_IP` (IP panel).

### Terminal web (menu Terminal)

Terminal web adalah shell root ke VM langsung dari browser, jadi tidak perlu PuTTY. Karena aksesnya sangat besar,
terminal dibatasi ketat:
- **Hanya admin.**
- **Hanya dari jaringan sekolah.** Terminal ditolak bila panel dibuka lewat NPMplus/internet; buka panel langsung
  di `http://IP-container:8080`.
- **Login di dalam layar terminal** (`wol-panel login:` lalu `Password:`, seperti konsol VM). Admin mana pun boleh
  login dengan akunnya sendiri, dan sesi serta rekamannya tercatat atas nama akun itu. Seperti konsol: setelah
  **Putuskan**, `exit`, sesi terputus, atau halaman dimuat ulang, harus login lagi untuk membuka terminal.
- **Izin per VM.** Di **Server**, klik **Izinkan terminal**, lalu jalankan perintah pasang yang muncul di VM itu.
  Kunci terminal terpisah dari kunci update dan hanya diterima dari IP panel.
- **Semua tampilan sesi direkam** di `/opt/wol-panel/vmlogs/terminal/`.
- **Ditutup otomatis** setelah 30 menit tanpa aktivitas.

Terminal **masuk sebagai user biasa di VM, bukan root**. Usernya adalah user yang menjalankan perintah pasang lewat
`sudo -i` (mis. `andi`), atau user biasa pertama di VM bila perintah itu dijalankan langsung sebagai root. Untuk menjadi
root, ketik `sudo -i` di terminal; sudo akan meminta password user tersebut di VM. Root hanya dipakai langsung bila VM
tidak punya user biasa. User yang dipakai tampil di pilihan VM, misalnya `absensi (andi@192.168.10.22)`.

VM yang dipasang sebelum fitur ini (wol-update v4) cukup diklik **Perbarui wol-update** di menu Server: wol-update v5
memindahkan kunci terminal dari root ke user biasa pertama di VM secara otomatis, tanpa pasang ulang.

Untuk mencabut izin, klik **Cabut terminal** di Server, lalu jalankan perintah pasang yang muncul di VM itu.
Kunci terminalnya akan dihapus dari VM.

Komponen tampilan terminal memakai [xterm.js](https://xtermjs.org) (lisensi MIT, lihat `static/XTERM-LICENSE.txt`).
Komponen ini disimpan di panel, jadi tidak memerlukan internet.

## 4. Akses dari luar sekolah

Pilih salah satu:

**A. Lewat subdomain + NPMplus — untuk akun Pengguna**
1. Cloudflare: buat record `wol.smkibupakusari.sch.id` → IP publik sekolah.
2. NPMplus: Proxy Host baru → forward ke `IP-panel:8080`, aktifkan SSL (Let's Encrypt) + *Force SSL*.
3. Di panel: **Pengaturan → Umum**, centang *Panel diakses lewat reverse proxy*, isi **IP reverse proxy** dengan IP
   container NPMplus, lalu Simpan.

Semua yang datang lewat subdomain dianggap dari luar. Di sana **akun admin tidak bisa masuk** (pesannya sama dengan
password salah agar tidak membocorkan apa pun, dan percobaannya tercatat di Riwayat), sesi admin yang sudah ada juga
ditolak, dan unduhan pemasang agen / skrip VM / skrip daftar komputer tidak dilayani. Terminal tetap hanya untuk
admin dari jaringan sekolah.

**B. Lewat VPN — untuk admin** — WireGuard di MikroTik atau Tailscale (alamat `100.64.x.x` dikenali sebagai VPN).
Setelah tersambung VPN, buka panel lewat IP lokalnya (bukan subdomain), seperti di sekolah.

> Jangan membuka port RDP 3389 langsung ke internet. Untuk remote desktop dari luar, pakai VPN atau
> aplikasi seperti AnyDesk/RustDesk.

## 5. Backup & pemulihan

`install.sh` memasang timer harian (02:00) yang menjalankan `/usr/local/sbin/wol-panel-backup`. Hasilnya
`/var/backups/wol-panel/wol_<tanggal>.tar.gz` (disimpan 14 hari, hanya bisa dibaca root) berisi `config.json` (akun,
komputer, kunci agen), `vm.json`, `scan.json`, wallpaper, dan kunci SSH panel — cukup untuk memulihkan panel tanpa
memasang ulang agen di setiap komputer. Rekaman terminal tidak ikut. Backup manual: `sudo wol-panel-backup`.

**Backup Master** menarik arsip ini seperti aplikasi lain: di Backup Master tambahkan sumber dengan templat
**WOL Panel**, lalu di container panel jalankan `siapkan-sumber.sh --folder /var/backups/wol-panel …` (perintahnya
tampil di menu Sumber Backup Master). Langkah pemulihan juga tampil di Backup Master. Manual:

```bash
systemctl stop wol-panel
tar -xzf wol_<tanggal>.tar.gz -C /opt/wol-panel
chown -R wolpanel:wolpanel /opt/wol-panel && chmod 600 /opt/wol-panel/config.json
systemctl start wol-panel
```

## 6. Kalau desktop tidak mau menyala

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
