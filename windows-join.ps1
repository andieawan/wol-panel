# WOL Panel - daftarkan komputer ini ke panel (TEMPLATE, diisi otomatis oleh panel).
# Jalankan perintah dari WOL Panel: Pengaturan -> Komputer -> Tambah lewat skrip,
# di PowerShell / Terminal (Admin) pada komputer yang ingin didaftarkan.
#
# Yang dilakukan:
#   1. Mendeteksi nama komputer, IP, subnet, dan MAC kartu jaringan kabel yang dipakai ke panel
#   2. Menyalakan pengaturan Wake-on-LAN di Windows (Wake on Magic Packet, izin membangunkan, Fast Startup mati)
#   3. Memasang agen WOL Panel (Matikan, pindai aplikasi, relay WOL)
#   4. Mendaftar ke panel; admin tinggal klik Tambahkan di panel

& {
    $Panel   = '__PANEL__'
    $PanelIp = '__PANEL_IP__'
    $Tok     = '__TOKEN__'

    $principal = New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'Gagal: buka PowerShell / Terminal sebagai Administrator lalu jalankan ulang perintahnya.' -ForegroundColor Red
        return
    }

    Write-Host '==> Mendeteksi kartu jaringan'
    $addr = Find-NetRoute -RemoteIPAddress $PanelIp -ErrorAction SilentlyContinue |
        Where-Object { $_.PSObject.Properties['PrefixLength'] -and $_.AddressFamily -eq 'IPv4' } | Select-Object -First 1
    if (-not $addr) { Write-Host "Gagal: komputer ini tidak bisa menjangkau panel $PanelIp." -ForegroundColor Red; return }
    $ad = Get-NetAdapter -InterfaceIndex $addr.InterfaceIndex -ErrorAction SilentlyContinue
    $isWifi = { param($a) "$($a.PhysicalMediaType)" -match '802\.11|Wireless' -or "$($a.InterfaceDescription)" -match 'Wi-?Fi|Wireless|WLAN' }
    $wifi = [bool](& $isWifi $ad)
    if ($wifi) {
        # WOL tidak bekerja lewat Wi-Fi: pakai kartu kabel bila ada
        $wired = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { -not (& $isWifi $_) } | Select-Object -First 1
        if ($wired) {
            Write-Host "    Terhubung lewat Wi-Fi; memakai kartu kabel $($wired.Name) untuk WOL." -ForegroundColor Yellow
            $ad = $wired; $wifi = $false
            $wa = Get-NetIPAddress -InterfaceIndex $wired.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($wa) { $addr = $wa }
        } else {
            Write-Host '    PERHATIAN: komputer ini hanya memakai Wi-Fi. Wake-on-LAN biasanya hanya bekerja lewat kabel LAN.' -ForegroundColor Yellow
        }
    }
    $mac = ($ad.MacAddress -replace '-', ':').ToUpper()
    Write-Host "    $($ad.Name) ($($ad.InterfaceDescription))  IP $($addr.IPAddress)/$($addr.PrefixLength)  MAC $mac"

    Write-Host '==> Menyalakan pengaturan Wake-on-LAN di Windows'
    $wol = $false
    try { Set-NetAdapterPowerManagement -Name $ad.Name -WakeOnMagicPacket Enabled -ErrorAction Stop; $wol = $true } catch {}
    foreach ($kw in '*WakeOnMagicPacket', 'WakeOnMagicPacket', 'S5WakeOnLan', 'EnablePME') {
        $p = Get-NetAdapterAdvancedProperty -Name $ad.Name -RegistryKeyword $kw -ErrorAction SilentlyContinue
        if ($p) { try { Set-NetAdapterAdvancedProperty -Name $ad.Name -RegistryKeyword $kw -RegistryValue 1 -NoRestart -ErrorAction Stop; $wol = $true } catch {} }
    }
    & powercfg.exe /deviceenablewake "$($ad.InterfaceDescription)" 2>&1 | Out-Null
    $fast = $false
    try {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -Value 0 -Type DWord -ErrorAction Stop
        $fast = $true
    } catch {}
    Write-Host ("    Wake on Magic Packet: " + $(if ($wol) { 'aktif' } else { 'tidak ditemukan, cek manual di Device Manager' }))
    Write-Host ("    Fast Startup: " + $(if ($fast) { 'dimatikan' } else { 'gagal dimatikan, matikan manual di Power Options' }))

    Write-Host '==> Mendaftar ke WOL Panel'
    $body = @{ host = $env:COMPUTERNAME; mac = $mac; ip = $addr.IPAddress; prefix = [int]$addr.PrefixLength
               adapter = [string]$ad.InterfaceDescription; wifi = $wifi; wol = $wol; fast = $fast } | ConvertTo-Json -Compress
    try {
        $agent = Invoke-RestMethod -Method Post -Uri "$Panel/join/$Tok" -Body ([Text.Encoding]::UTF8.GetBytes($body)) `
                     -ContentType 'application/json; charset=utf-8' -TimeoutSec 30
    } catch {
        Write-Host "Gagal mendaftar: $($_.Exception.Message)" -ForegroundColor Red; return
    }
    if ("$agent" -notmatch 'pemasang agen Windows') { Write-Host "Gagal mendaftar: $agent" -ForegroundColor Red; return }

    Write-Host '==> Memasang agen'
    & ([scriptblock]::Create([string]$agent))

    Write-Host ''
    Write-Host "Komputer $env:COMPUTERNAME terdaftar. Di WOL Panel buka Pengaturan -> Komputer, lalu klik Tambahkan." -ForegroundColor Green
    Write-Host 'Pastikan juga Wake-on-LAN aktif di BIOS (biasanya: Power Management -> Wake on LAN / Power On by PCI-E).'
}
