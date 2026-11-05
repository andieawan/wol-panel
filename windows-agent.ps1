# WOL Panel - pemasang agen Windows (untuk tombol "Matikan")
# File ini adalah TEMPLATE. Jangan dijalankan langsung: buka Pengaturan -> Agen di WOL Panel,
# lalu jalankan perintah yang ditampilkan di PowerShell/Terminal (Admin) pada komputer tujuan.
#
# Yang dipasang:
#   - C:\ProgramData\WOLPanelAgent\agent.ps1  (hanya bisa dibaca SYSTEM & Administrators)
#   - Scheduled Task "WOL Panel Agent" (berjalan sebagai SYSTEM saat Windows menyala)
#   - Aturan firewall: port __PORT__ hanya untuk IP panel __PANEL_IP__

& {
    $Port    = __PORT__
    $PanelIp = '__PANEL_IP__'
    $Dir     = Join-Path $env:ProgramData 'WOLPanelAgent'
    $Task    = 'WOL Panel Agent'
    $Rule    = 'WOL Panel Agent'

    $principal = New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'Gagal: buka PowerShell / Terminal sebagai Administrator lalu jalankan ulang perintahnya.' -ForegroundColor Red
        return
    }

    $AgentCode = @'
# WOL Panel Agent - menerima perintah matikan dari WOL Panel
$Secret  = '__SECRET__'
$Port    = __PORT__
$PanelIp = '__PANEL_IP__'
$PanelPort = __PANEL_PORT__
$Log     = Join-Path (Join-Path $env:ProgramData 'WOLPanelAgent') 'agent.log'
$Seen    = @{}
$AgentVersion = 10
$script:LastBeat = [datetime]::MinValue
$AgentFile = Join-Path (Join-Path $env:ProgramData 'WOLPanelAgent') 'agent.ps1'
$script:By = ''

function Write-Log([string]$t) {
    try {
        if ((Test-Path $Log) -and (Get-Item $Log).Length -gt 1MB) { Remove-Item $Log -Force }
        Add-Content -Path $Log -Value ('{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $t)
    } catch {}
}

function Send-Text($ctx, [int]$code, [string]$text) {
    try {
        $b = [Text.Encoding]::UTF8.GetBytes($text)
        $ctx.Response.StatusCode = $code
        $ctx.Response.ContentType = 'text/plain; charset=utf-8'
        $ctx.Response.ContentLength64 = $b.Length
        $ctx.Response.OutputStream.Write($b, 0, $b.Length)
    } catch {} finally { try { $ctx.Response.Close() } catch {} }
}

function Get-Sig([string]$msg) {
    $h = New-Object System.Security.Cryptography.HMACSHA256 (,[Text.Encoding]::UTF8.GetBytes($Secret))
    try { return -join ($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($msg)) | ForEach-Object { $_.ToString('x2') }) }
    finally { $h.Dispose() }
}

function Test-Same([string]$a, [string]$b) {
    if ($a.Length -ne $b.Length) { return $false }
    $d = 0
    for ($i = 0; $i -lt $a.Length; $i++) { $d = $d -bor ([int][char]$a[$i] -bxor [int][char]$b[$i]) }
    return ($d -eq 0)
}

function Get-Sha256([string]$text) {
    $s = [Security.Cryptography.SHA256]::Create()
    try { return -join ($s.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) | ForEach-Object { $_.ToString('x2') }) }
    finally { $s.Dispose() }
}

function Send-Json($ctx, [int]$code, $obj) {
    try {
        $b = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $obj -Depth 5 -Compress))
        $ctx.Response.StatusCode = $code
        $ctx.Response.ContentType = 'application/json; charset=utf-8'
        $ctx.Response.ContentLength64 = $b.Length
        $ctx.Response.OutputStream.Write($b, 0, $b.Length)
    } catch {} finally { try { $ctx.Response.Close() } catch {} }
}

# ---------------------------------------------------------------- pemindai aplikasi
$UninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall'

function Get-Profiles {
    Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object { -not $_.Special -and $_.LocalPath -and ($_.SID -like 'S-1-5-21-*' -or $_.SID -like 'S-1-12-1-*') }
}

# Membuka registry pengguna; bila pengguna tidak sedang login, hive-nya dimuat sementara.
function Open-UserHive($p) {
    $live = "Registry::HKEY_USERS\$($p.SID)"
    if (Test-Path $live) { return @{ Root = $live; Temp = $null } }
    $dat = Join-Path $p.LocalPath 'NTUSER.DAT'
    if (-not (Test-Path -LiteralPath $dat)) { return $null }
    $tmp = 'WOLSCAN_' + ($p.SID -replace '-', '_')
    & reg.exe load "HKU\$tmp" "$dat" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { return $null }
    return @{ Root = "Registry::HKEY_USERS\$tmp"; Temp = $tmp }
}

function Close-UserHive($h) {
    if ($h -and $h.Temp) {
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
        & reg.exe unload "HKU\$($h.Temp)" 2>&1 | Out-Null
    }
}

function Read-UninstallKey([string]$path, [string]$idPrefix, [string]$scope, $list) {
    if (-not (Test-Path $path)) { return }
    foreach ($k in Get-ChildItem -Path $path -ErrorAction SilentlyContinue) {
        $v = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
        if (-not $v -or -not $v.DisplayName) { continue }
        if ($v.SystemComponent -eq 1 -or $v.ParentKeyName -or ([string]$v.ReleaseType) -match 'Update|Hotfix') { continue }
        Add-KnownDir ([string]$v.InstallLocation); Add-KnownDir ([string]$v.DisplayIcon); Add-KnownDir ([string]$v.UninstallString)
        $list.Add([pscustomobject]@{
            id = "$idPrefix|$($k.PSChildName)"; name = ([string]$v.DisplayName).Trim(); version = [string]$v.DisplayVersion
            publisher = [string]$v.Publisher; scope = $scope; kind = 'win32'; date = [string]$v.InstallDate })
    }
}

# Aplikasi yang hanya punya pintasan di Start menu (portable / tidak terdaftar di daftar Uninstall Windows)
$script:KnownDirs = New-Object System.Collections.Generic.List[string]

function Add-KnownDir([string]$p) {
    if (-not $p) { return }
    $p = $p.Trim()
    if ($p -match '^"([^"]+)"') { $p = $Matches[1] }
    $p = (($p.Trim('"') -replace ',\s*-?\d+$', '') -replace '\s+/.*$', '').TrimEnd('\')
    if ($p -match '(?i)\.(exe|ico|dll)$' -and $p.Contains('\')) { $p = $p.Substring(0, $p.LastIndexOf('\')) }
    if ($p -match '(?i)\\(_?uninst(all)?(er)?)$') { $p = $p.Substring(0, $p.LastIndexOf('\')) }   # uninstaller di subfolder: pakai folder aplikasinya
    if (-not $p -or ($p.Split('\') | Where-Object { $_ }).Count -lt 3) { return }   # jangan pakai folder terlalu umum (mis. C:\Program Files)
    $script:KnownDirs.Add($p.ToLower() + '\')
}

function Test-StartMenuLink([string]$lnk) {
    $roots = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\")
    foreach ($p in Get-Profiles) { $roots += (Join-Path $p.LocalPath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs') + '\' }
    try { $full = [IO.Path]::GetFullPath($lnk) } catch { return $false }
    if ($full -notlike '*.lnk') { return $false }
    foreach ($r in $roots) { if ($full.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)) { return $true } }
    return $false
}

function Add-ShortcutApps($list) {
    $sh = New-Object -ComObject WScript.Shell
    $names = @{}; foreach ($a in $list) { if ($a.name) { $names[([string]$a.name).ToLower()] = $true } }
    $roots = @(@{ dir = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"; scope = 'Semua pengguna' })
    foreach ($p in Get-Profiles) { $roots += @{ dir = (Join-Path $p.LocalPath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs'); scope = (Split-Path $p.LocalPath -Leaf) } }
    $seen = @{}
    $win = $env:SystemRoot.ToLower() + '\'
    foreach ($r in $roots) {
        if (-not (Test-Path -LiteralPath $r.dir)) { continue }
        foreach ($l in Get-ChildItem -LiteralPath $r.dir -Filter *.lnk -Recurse -ErrorAction SilentlyContinue) {
            try { $t = [string]$sh.CreateShortcut($l.FullName).TargetPath } catch { continue }
            if (-not $t -or $t -notmatch '(?i)\.exe$' -or -not (Test-Path -LiteralPath $t -PathType Leaf)) { continue }
            $tl = $t.ToLower()
            if ($tl.StartsWith($win) -or $tl -like '*\windowsapps\*' -or $seen[$tl]) { continue }
            $seen[$tl] = $true
            $covered = $false
            foreach ($k in $script:KnownDirs) { if ($tl.StartsWith($k)) { $covered = $true; break } }
            if ($covered) { continue }
            $nm = [IO.Path]::GetFileNameWithoutExtension($l.Name)
            $nl = $nm.ToLower()
            if ($nl -match 'uninstall|hapus|readme|help|bantuan|website|manual|license') { continue }
            $dup = $names[$nl]
            if (-not $dup -and $nl.Length -ge 4) {
                foreach ($k in $names.Keys) { if ($k.Length -ge 4 -and ($k.Contains($nl) -or $nl.Contains($k))) { $dup = $true; break } }
            }
            if ($dup) { continue }
            $fi = Get-Item -LiteralPath $t
            $list.Add([pscustomobject]@{
                id = 'LNK|' + $l.FullName; name = $nm; version = [string]$fi.VersionInfo.ProductVersion
                publisher = [string]$fi.VersionInfo.CompanyName; scope = $r.scope; kind = 'shortcut'
                date = $fi.CreationTime.ToString('yyyyMMdd'); target = $t })
            $names[$nl] = $true
        }
    }
}

function Get-Apps {
    $list = New-Object System.Collections.Generic.List[object]
    $script:KnownDirs.Clear()
    Read-UninstallKey "HKLM:\$UninstallKey" 'M64' 'Semua pengguna' $list
    Read-UninstallKey "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" 'M32' 'Semua pengguna' $list
    foreach ($p in Get-Profiles) {
        $h = Open-UserHive $p
        if (-not $h) { continue }
        try {
            Read-UninstallKey "$($h.Root)\$UninstallKey" "U:$($p.SID)" (Split-Path $p.LocalPath -Leaf) $list
            Read-UninstallKey "$($h.Root)\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" "U32:$($p.SID)" (Split-Path $p.LocalPath -Leaf) $list
        }
        finally { Close-UserHive $h }
    }
    try { Add-ShortcutApps $list } catch {}
    try {
        # paket yang ikut terpasang bersama Windows / dari pabrikan (bawaan)
        $prov = @{}
        try { Get-AppxProvisionedPackage -Online -ErrorAction Stop | ForEach-Object { $prov[$_.DisplayName] = $true } } catch {}
        foreach ($a in Get-AppxPackage -AllUsers -ErrorAction Stop) {
            if ($a.IsFramework -or $a.IsResourcePackage -or $a.NonRemovable -or "$($a.SignatureKind)" -eq 'System') { continue }
            $users = @($a.PackageUserInformation | ForEach-Object { ("$($_.UserSecurityId.Username)" -split '\\')[-1] } | Where-Object { $_ }) -join ', '
            $list.Add([pscustomobject]@{
                id = "APPX|$($a.PackageFullName)"; name = [string]$a.Name; version = [string]$a.Version
                publisher = ([string]$a.Publisher -replace '^CN=([^,]+).*$', '$1'); scope = $(if ($users) { "Store ($users)" } else { 'Store' })
                kind = 'store'; date = ''; provisioned = [bool]$prov[$a.Name]; signature = "$($a.SignatureKind)" })
        }
    } catch {}
    return $list
}

function Invoke-Cmdline([string]$cmdline, [int]$timeoutSec) {
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = "$env:SystemRoot\System32\cmd.exe"
    $psi.Arguments = '/d /s /c "' + $cmdline + '"'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi)
    if (-not $p.WaitForExit($timeoutSec * 1000)) {
        & taskkill.exe /PID $p.Id /T /F 2>&1 | Out-Null
        return -999
    }
    return $p.ExitCode
}

# Folder utama aplikasi di dalam profil pengguna, mis. C:\Users\siswa\AppData\Local\Roblox
function Get-UserAppRoot([string]$path, [string]$profileDir) {
    if (-not $path) { return $null }
    $path = $path.Trim()
    if ($path -match '^"([^"]+)"') { $path = $Matches[1] } elseif ($path -match '^(.+?\.exe)\b') { $path = $Matches[1] }
    try { $full = [IO.Path]::GetFullPath($path) } catch { return $null }
    $prefix = $profileDir.TrimEnd('\') + '\'
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return $null }
    $parts = $full.Substring($prefix.Length) -split '\\'
    if ($parts.Count -lt 3 -or $parts[0] -ne 'AppData' -or ($parts[1] -ne 'Local' -and $parts[1] -ne 'Roaming')) { return $null }
    $i = 2
    if ($parts[1] -eq 'Local' -and $parts[2] -eq 'Programs') { $i = 3 }
    $generic = @('Microsoft', 'Packages', 'Temp', 'Google', 'Mozilla', 'Apps', 'Comms', 'CrashDumps', 'Publishers', 'D3DSCache', 'Programs')
    if ($parts.Count -gt $i -and $generic -contains $parts[$i]) { $i++ }
    if ($parts.Count -le $i) { return $null }
    # path berupa file langsung di AppData\Local (bukan di dalam folder aplikasi) tidak dihapus
    if ($parts.Count -eq $i + 1 -and -not (Test-Path -LiteralPath $full -PathType Container)) { return $null }
    $root = $prefix + (($parts[0..$i]) -join '\')
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return $null }
    return $root
}

function Remove-UserShortcuts([string]$profileDir, [string]$root) {
    $dirs = @("$profileDir\Desktop", "$profileDir\AppData\Roaming\Microsoft\Windows\Start Menu\Programs")
    $sh = New-Object -ComObject WScript.Shell
    foreach ($d in $dirs) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        foreach ($l in Get-ChildItem -LiteralPath $d -Filter *.lnk -Recurse -ErrorAction SilentlyContinue) {
            try { if ($sh.CreateShortcut($l.FullName).TargetPath -like "$root\*") { Remove-Item -LiteralPath $l.FullName -Force } } catch {}
        }
    }
}

function Invoke-Uninstall([string]$id) {
    if ($id -like 'LNK|*') {
        $lnk = $id.Substring(4)
        if (-not (Test-StartMenuLink $lnk)) { return @{ ok = $false; msg = 'ID aplikasi tidak valid.' } }
        if (-not (Test-Path -LiteralPath $lnk)) { return @{ ok = $true; msg = 'Pintasan aplikasi sudah tidak ada.' } }
        $t = [string](New-Object -ComObject WScript.Shell).CreateShortcut($lnk).TargetPath
        $prof = Get-Profiles | Where-Object { $t -like "$($_.LocalPath)\*" } | Select-Object -First 1
        $root = if ($prof) { Get-UserAppRoot $t $prof.LocalPath } else { $null }
        if ($root) {
            Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path -like "$root\*" } | ForEach-Object { try { $_.Kill() } catch {} }
            Start-Sleep -Milliseconds 800
            Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
            Remove-UserShortcuts $prof.LocalPath $root
            Remove-Item -LiteralPath $lnk -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path -LiteralPath $root)) { Write-Log "Hapus paksa (pintasan) $root"; return @{ ok = $true; msg = "Dihapus (folder $root dibersihkan)." } }
            return @{ ok = $false; msg = 'Sebagian file masih dipakai. Coba lagi setelah pengguna logout.' }
        }
        return @{ ok = $false; msg = "Aplikasi ini tidak punya uninstaller terdaftar. Hapus manual foldernya: $(Split-Path $t -Parent)" }
    }
    if ($id -like 'APPX|*') {
        try { Remove-AppxPackage -Package $id.Substring(5) -AllUsers -ErrorAction Stop; return @{ ok = $true; msg = 'Aplikasi Store dihapus untuk semua pengguna.' } }
        catch { return @{ ok = $false; msg = "Gagal menghapus aplikasi Store: $($_.Exception.Message)" } }
    }
    $prefix, $keyName = $id -split '\|', 2
    if (-not $keyName -or $keyName -match '[\\/]') { return @{ ok = $false; msg = 'ID aplikasi tidak valid.' } }
    $hive = $null; $profileDir = $null
    switch -regex ($prefix) {
        '^M64$' { $base = "HKLM:\$UninstallKey" }
        '^M32$' { $base = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' }
        '^U32:(S-1-(?:5-21|12-1)-[\d-]+)$' {
            $sid = $Matches[1]
            $p = Get-Profiles | Where-Object { $_.SID -eq $sid } | Select-Object -First 1
            if (-not $p) { return @{ ok = $false; msg = 'Profil pengguna tidak ditemukan.' } }
            $profileDir = $p.LocalPath
            $hive = Open-UserHive $p
            if (-not $hive) { return @{ ok = $false; msg = 'Registry pengguna tidak bisa dibuka.' } }
            $base = "$($hive.Root)\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        }
        '^U:(S-1-(?:5-21|12-1)-[\d-]+)$' {
            $sid = $Matches[1]
            $p = Get-Profiles | Where-Object { $_.SID -eq $sid } | Select-Object -First 1
            if (-not $p) { return @{ ok = $false; msg = 'Profil pengguna tidak ditemukan.' } }
            $profileDir = $p.LocalPath
            $hive = Open-UserHive $p
            if (-not $hive) { return @{ ok = $false; msg = 'Registry pengguna tidak bisa dibuka.' } }
            $base = "$($hive.Root)\$UninstallKey"
        }
        default { return @{ ok = $false; msg = 'ID aplikasi tidak valid.' } }
    }
    try {
        $keyPath = "$base\$keyName"
        $v = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
        if (-not $v) { return @{ ok = $true; msg = 'Aplikasi sudah tidak terpasang.' } }
        $name = [string]$v.DisplayName
        $u = [string]$v.UninstallString
        $cmd = [string]$v.QuietUninstallString
        if (-not $cmd) {
            if ($v.WindowsInstaller -eq 1 -or $u -match 'msiexec') {
                $guid = if ($keyName -match '^\{[0-9A-Fa-f-]{36}\}$') { $keyName } else { [regex]::Match($u, '\{[0-9A-Fa-f-]{36}\}').Value }
                if ($guid) { $cmd = "msiexec.exe /x $guid /qn /norestart" }
            } elseif ($u -match 'unins\d{3}\.exe') {
                $cmd = "$u /VERYSILENT /SUPPRESSMSGBOXES /NORESTART"
            }
        }
        $note = ''
        if ($cmd) {
            Write-Log "Uninstall $name : $cmd"
            $code = Invoke-Cmdline $cmd 180
            if ($code -eq -999) { $note = 'Uninstaller tidak selesai dalam 3 menit. ' }
            elseif ($code -ne 0 -and $code -ne 3010 -and $code -ne 1605) { $note = "Uninstaller selesai dengan kode $code. " }
        }
        if (-not (Test-Path $keyPath)) { return @{ ok = $true; msg = "$name berhasil di-uninstall." } }

        # Aplikasi yang terpasang di profil pengguna (mis. Roblox) dibersihkan langsung
        if ($profileDir) {
            $root = $null
            foreach ($cand in @([string]$v.InstallLocation, $u, [string]$v.DisplayIcon)) {
                $root = Get-UserAppRoot $cand $profileDir
                if ($root) { break }
            }
            if ($root) {
                Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path -like "$root\*" } |
                    ForEach-Object { try { $_.Kill() } catch {} }
                Start-Sleep -Milliseconds 800
                Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
                Remove-UserShortcuts $profileDir $root
                if (-not (Test-Path -LiteralPath $root)) {
                    Remove-Item -Path $keyPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log "Hapus paksa $name : $root"
                    return @{ ok = $true; msg = "$name dihapus (folder $root dibersihkan)." }
                }
                return @{ ok = $false; msg = "${note}Sebagian file $name masih dipakai. Coba lagi setelah pengguna logout." }
            }
        }
        if (-not $cmd) { return @{ ok = $false; msg = "$name tidak punya uninstaller otomatis. Uninstall manual lewat Settings > Apps di komputer itu." } }
        return @{ ok = $false; msg = "${note}$name masih terpasang. Uninstall manual lewat Settings > Apps di komputer itu." }
    } finally {
        Close-UserHive $hive
    }
}

# ---------------------------------------------------------------- wallpaper
# Gambar diunduh dari panel (URL harus ke IP panel) dan dicek SHA-256-nya, lalu dipasang untuk semua profil
# pengguna. Pengguna yang sedang login langsung berganti lewat tugas yang berjalan di sesi mereka.
$WpDir = Join-Path $env:SystemRoot 'Web\Wallpaper\WOLPanel'   # bisa dibaca semua pengguna, ditulis admin
$WpStyles = @{ fill = @('10', '0'); fit = @('6', '0'); stretch = @('2', '0'); center = @('0', '0'); tile = @('0', '1'); span = @('22', '0') }

function Set-DesktopKey([string]$root, [string]$path, $st) {
    $k = "$root\Control Panel\Desktop"
    if (-not (Test-Path $k)) { return }
    Set-ItemProperty -Path $k -Name Wallpaper -Value $path
    Set-ItemProperty -Path $k -Name WallpaperStyle -Value $st[0]
    Set-ItemProperty -Path $k -Name TileWallpaper -Value $st[1]
}

function Set-Wallpaper($c) {
    $st = $WpStyles[[string]$c.style]; if (-not $st) { $st = $WpStyles['fill'] }
    New-Item -ItemType Directory -Path $WpDir -Force | Out-Null
    if ([string]$c.mode -eq 'default') {
        $path = Join-Path $env:SystemRoot 'Web\Wallpaper\Windows\img0.jpg'
        if (-not (Test-Path -LiteralPath $path)) {
            $f = Get-ChildItem (Join-Path $env:SystemRoot 'Web\Wallpaper\Windows') -Filter *.jpg -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $f) { return @{ ok = $false; msg = 'Wallpaper bawaan Windows tidak ditemukan.' } }
            $path = $f.FullName
        }
    } else {
        $sha = ([string]$c.sha256).ToUpper()
        $ext = [string]$c.ext
        try { $u = [Uri][string]$c.url } catch { return @{ ok = $false; msg = 'URL gambar tidak valid.' } }
        if ($u.Scheme -ne 'http' -or $u.Host -ne $PanelIp -or $sha -notmatch '^[0-9A-F]{64}$' -or $ext -notmatch '^(jpg|png)$') {
            return @{ ok = $false; msg = 'Gambar harus dari panel ini.' }
        }
        $path = Join-Path $WpDir ("wallpaper-" + $sha.Substring(0, 12).ToLower() + "." + $ext)
        if (-not (Test-Path -LiteralPath $path) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $sha) {
            $tmp = Join-Path $WpDir 'unduh.tmp'
            try { Invoke-WebRequest -Uri $u -OutFile $tmp -UseBasicParsing -TimeoutSec 90 }
            catch { return @{ ok = $false; msg = "Gagal mengunduh gambar dari panel: $($_.Exception.Message)" } }
            if ((Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash -ne $sha) {
                Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
                return @{ ok = $false; msg = 'Gambar rusak saat diunduh (hash tidak cocok).' }
            }
            Move-Item -LiteralPath $tmp -Destination $path -Force
        }
        Get-ChildItem $WpDir -Filter 'wallpaper-*' | Where-Object { $_.FullName -ne $path } | Remove-Item -Force -ErrorAction SilentlyContinue
    }

    # semua profil pengguna (yang sedang login maupun tidak) + profil bawaan untuk pengguna baru
    $n = 0
    foreach ($p in Get-Profiles) {
        $h = Open-UserHive $p
        if (-not $h) { continue }
        try { Set-DesktopKey $h.Root $path $st; $n++ } catch {} finally { Close-UserHive $h }
    }
    $def = Join-Path $env:SystemDrive 'Users\Default\NTUSER.DAT'
    if (Test-Path -LiteralPath $def) {
        & reg.exe load 'HKU\WOLWP_DEFAULT' "$def" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            try { Set-DesktopKey 'Registry::HKEY_USERS\WOLWP_DEFAULT' $path $st } catch {} finally {
                [GC]::Collect(); [GC]::WaitForPendingFinalizers(); & reg.exe unload 'HKU\WOLWP_DEFAULT' 2>&1 | Out-Null }
        }
    }

    # kunci: kebijakan komputer agar siswa tidak bisa mengganti wallpaper
    $pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $ad  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop'
    if ($c.lock) {
        New-Item -Path $pol -Force | Out-Null; New-Item -Path $ad -Force | Out-Null
        Set-ItemProperty -Path $pol -Name Wallpaper -Value $path
        Set-ItemProperty -Path $pol -Name WallpaperStyle -Value $st[0]
        Set-ItemProperty -Path $ad -Name NoChangingWallPaper -Value 1 -Type DWord
    } else {
        Remove-ItemProperty -Path $pol -Name Wallpaper, WallpaperStyle -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $ad -Name NoChangingWallPaper -ErrorAction SilentlyContinue
    }

    # pengguna yang sedang login: terapkan sekarang di sesi mereka
    $apply = Join-Path $WpDir 'terapkan.ps1'
    Set-Content -Path $apply -Encoding UTF8 -Value @(
        '$p = (Get-ItemProperty ''HKCU:\Control Panel\Desktop'').Wallpaper',
        'Add-Type -TypeDefinition ''using System.Runtime.InteropServices; public class WolWp { [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int SystemParametersInfo(int a, int b, string c, int d); }''',
        '[WolWp]::SystemParametersInfo(20, 0, $p, 3) | Out-Null')
    $online = 0
    try {
        $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$apply`""
        $prn = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited
        Register-ScheduledTask -TaskName 'WOL Panel Wallpaper' -Action $act -Principal $prn -Force `
            -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 2)) | Out-Null
        Start-ScheduledTask -TaskName 'WOL Panel Wallpaper'
        $online = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue).Count
    } catch {}
    $what = if ([string]$c.mode -eq 'default') { 'Wallpaper bawaan Windows' } else { 'Wallpaper baru' }
    $msg = "$what dipasang untuk $n profil" + $(if ($online) { ", langsung tampil di $online sesi yang sedang login" } else { ', tampil saat pengguna login' }) +
           $(if ($c.lock) { '; dikunci.' } else { '.' })
    return @{ ok = $true; msg = $msg }
}

function Get-WallpaperStatus {
    # wallpaper tiap profil pengguna saat ini: path + SHA-256 filenya, untuk dibandingkan panel dengan yang disetujui
    $hashOf = { param($p) if ($p -and (Test-Path -LiteralPath $p -PathType Leaf)) { try { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower() } catch { '' } } else { '' } }
    $list = New-Object System.Collections.Generic.List[object]
    $active = @{}
    foreach ($pr in Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue) {
        try { $o = Invoke-CimMethod -InputObject $pr -MethodName GetOwner -ErrorAction Stop; if ($o.User) { $active[$o.User.ToLower()] = $true } } catch {}
    }
    foreach ($p in Get-Profiles) {
        $h = Open-UserHive $p
        if (-not $h) { continue }
        try {
            $v = Get-ItemProperty -Path "$($h.Root)\Control Panel\Desktop" -ErrorAction SilentlyContinue
            $path = [string]$v.Wallpaper
            $user = Split-Path $p.LocalPath -Leaf
            $list.Add([pscustomobject]@{ user = $user; path = $path; sha256 = (& $hashOf $path); online = [bool]$active[$user.ToLower()] })
        } finally { Close-UserHive $h }
    }
    $def = Join-Path $env:SystemRoot 'Web\Wallpaper\Windows\img0.jpg'
    $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
    return @{ ok = $true; profiles = @($list); default_sha256 = (& $hashOf $def); locked = [bool]$pol.Wallpaper }
}

# ---------------------------------------------------------------- relay Wake-on-LAN
# Panel di subnet lain tidak bisa mengirim broadcast ke subnet ini; agen yang hidup di subnet ini mengirimkannya.
function Send-Wol([string]$mac, $targets, [int]$port) {
    if ($mac -notmatch '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$') { return @{ ok = $false; msg = 'MAC tidak valid' } }
    $m = [byte[]]($mac -split ':' | ForEach-Object { [Convert]::ToByte($_, 16) })
    $pkt = New-Object byte[] 102
    for ($i = 0; $i -lt 6; $i++) { $pkt[$i] = 255 }
    for ($i = 1; $i -le 16; $i++) { [Array]::Copy($m, 0, $pkt, $i * 6, 6) }
    $ports = @($port); if ($port -eq 9) { $ports += 7 }
    $udp = New-Object Net.Sockets.UdpClient
    $udp.EnableBroadcast = $true
    $sent = 0
    try {
        for ($r = 0; $r -lt 3; $r++) {
            foreach ($t in @($targets)) {
                $ip = $null
                if (-not [Net.IPAddress]::TryParse([string]$t, [ref]$ip) -or $ip.AddressFamily -ne 'InterNetwork') { continue }
                foreach ($p in $ports) { try { [void]$udp.Send($pkt, $pkt.Length, (New-Object Net.IPEndPoint($ip, $p))); $sent++ } catch {} }
            }
            Start-Sleep -Milliseconds 100
        }
    } finally { $udp.Close() }
    return @{ ok = ($sent -gt 0); msg = "$sent paket dikirim" }
}

# ---------------------------------------------------------------- lapor IP ke panel
# Saat agen mulai lalu tiap 5 menit: panel memperbarui IP komputer ini bila berubah (DHCP).
function Send-Beat {
    if (((Get-Date) - $script:LastBeat).TotalMinutes -lt 5) { return }  # gagal (jaringan belum siap): dicoba lagi 30 detik kemudian
    try {
        $r = Find-NetRoute -RemoteIPAddress $PanelIp -ErrorAction Stop |
            Where-Object { $_.PSObject.Properties['PrefixLength'] -and $_.AddressFamily -eq 'IPv4' } | Select-Object -First 1
        if (-not $r) { return }
        $mac = ((Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -ErrorAction Stop).MacAddress -replace '-', ':').ToUpper()
        $ts = [string][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $nonce = [guid]::NewGuid().ToString('N')
        $ip = [string]$r.IPAddress; $prefix = [int]$r.PrefixLength
        $body = @{ fp = (Get-Sha256 "wol-fp|$Secret").Substring(0, 16); ts = $ts; nonce = $nonce; ip = $ip; prefix = $prefix
                   mac = $mac; version = $AgentVersion; sig = (Get-Sig "beat|$ts|$nonce|$ip|$prefix|$mac|$AgentVersion") } | ConvertTo-Json -Compress
        [void](Invoke-WebRequest -Uri "http://${PanelIp}:$PanelPort/agent/beat" -Method Post -Body $body -ContentType 'application/json' `
                   -UseBasicParsing -TimeoutSec 5)
        $script:LastBeat = Get-Date
    } catch {}
}

# ---------------------------------------------------------------- permintaan dari panel
function Test-Signed($ctx, [string]$kind, [string]$extra) {
    $req   = $ctx.Request
    $ts    = [string]$req.Headers['X-WOL-Time']
    $nonce = [string]$req.Headers['X-WOL-Nonce']
    $by    = [string]$req.Headers['X-WOL-User']
    $sig   = [string]$req.Headers['X-WOL-Signature']
    if ($ts -notmatch '^\d{9,11}$' -or $nonce -notmatch '^[0-9a-f]{16,64}$' -or
        $by -notmatch '^[A-Za-z0-9._-]{0,32}$' -or $sig -notmatch '^[0-9a-f]{64}$') {
        Send-Text $ctx 400 'bad request'; return $false
    }
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if ([Math]::Abs($now - [long]$ts) -gt 120) { Send-Text $ctx 401 'clock'; Write-Log 'Ditolak: selisih jam panel dan komputer lebih dari 2 menit'; return $false }
    if (-not (Test-Same (Get-Sig "$kind|$ts|$nonce|$extra|$by") $sig)) { Send-Text $ctx 401 'unauthorized'; Write-Log 'Ditolak: tanda tangan tidak cocok'; return $false }
    if ($Seen.ContainsKey($nonce)) { Send-Text $ctx 401 'replay'; return $false }
    foreach ($k in @($Seen.Keys)) { if ($now - $Seen[$k] -gt 300) { $Seen.Remove($k) } }
    $Seen[$nonce] = $now
    $script:By = $by
    return $true
}

function Handle($ctx) {
    $req  = $ctx.Request
    $from = $req.RemoteEndPoint.Address.ToString()
    $path = $req.Url.AbsolutePath

    if ($req.HttpMethod -eq 'GET' -and $path -eq '/hello') {
        # perkenalan untuk fitur "Cari di jaringan": nama, MAC, IP, subnet, dan sidik kunci (bukan kuncinya)
        if ($from -ne $PanelIp) { Send-Text $ctx 403 'forbidden'; return }
        $la = $req.LocalEndPoint.Address.ToString()
        $mac = ''; $prefix = 0
        try {
            $ipo = Get-NetIPAddress -IPAddress $la -ErrorAction Stop | Select-Object -First 1
            $prefix = [int]$ipo.PrefixLength
            $mac = ((Get-NetAdapter -InterfaceIndex $ipo.InterfaceIndex -ErrorAction Stop).MacAddress -replace '-', ':').ToUpper()
        } catch {}
        Send-Json $ctx 200 @{ ok = $true; version = $AgentVersion; host = $env:COMPUTERNAME; ip = $la; prefix = $prefix; mac = $mac
                              fp = (Get-Sha256 "wol-fp|$Secret").Substring(0, 16) }
        return
    }

    if ($req.HttpMethod -eq 'GET' -and $path -eq '/ping') {
        if ($from -eq $PanelIp -or $from -eq '127.0.0.1' -or $from -eq '::1') { Send-Text $ctx 200 'ok' }
        else { Send-Text $ctx 403 'forbidden' }
        return
    }
    if ($from -ne $PanelIp) { Send-Text $ctx 403 'forbidden'; Write-Log "Ditolak dari $from (bukan IP panel)"; return }
    if ($req.HttpMethod -ne 'POST') { Send-Text $ctx 404 'not found'; return }

    if ($path -eq '/shutdown') {
        $delay = [string]$req.Headers['X-WOL-Delay']
        if ($delay -notmatch '^\d{1,3}$') { Send-Text $ctx 400 'bad request'; return }
        if (-not (Test-Signed $ctx 'shutdown' $delay)) { return }
        $d = [Math]::Min([int]$delay, 600)
        Send-Text $ctx 200 'ok'
        Write-Log "Matikan dalam $d detik, diminta oleh $script:By"
        & "$env:SystemRoot\System32\shutdown.exe" /s /f /t $d /c "Komputer dimatikan dari WOL Panel oleh $script:By" | Out-Null
        return
    }

    if ($path -eq '/cmd') {
        if ($req.ContentLength64 -gt 1048576) { Send-Text $ctx 413 'too large'; return }
        $reader = New-Object IO.StreamReader($req.InputStream, [Text.Encoding]::UTF8)
        $body = $reader.ReadToEnd(); $reader.Close()
        if (-not (Test-Signed $ctx 'cmd' (Get-Sha256 $body))) { return }
        try { $c = $body | ConvertFrom-Json } catch { Send-Json $ctx 400 @{ ok = $false; msg = 'JSON tidak valid' }; return }
        switch ([string]$c.action) {
            'scan' {
                $apps = Get-Apps
                $osdate = ''
                try { $osdate = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).InstallDate.ToString('yyyyMMdd') } catch {}
                Write-Log "Pindai aplikasi: $($apps.Count) ditemukan"
                Send-Json $ctx 200 @{ ok = $true; version = $AgentVersion; osdate = $osdate; apps = @($apps) }
            }
            'uninstall' {
                $r = Invoke-Uninstall ([string]$c.id)
                Write-Log "Uninstall diminta $script:By : $($r.msg)"
                Send-Json $ctx 200 $r
            }
            'wpstatus' {
                Send-Json $ctx 200 (Get-WallpaperStatus)
            }
            'wallpaper' {
                $r = Set-Wallpaper $c
                Write-Log "Wallpaper diminta $script:By : $($r.msg)"
                Send-Json $ctx 200 $r
            }
            'wol' {
                $r = Send-Wol ([string]$c.mac) $c.targets ([int]$c.port)
                Write-Log "Relay WOL ke $($c.mac) diminta $script:By : $($r.msg)"
                Send-Json $ctx 200 $r
            }
            'info' {
                Send-Json $ctx 200 @{ ok = $true; version = $AgentVersion; host = $env:COMPUTERNAME }
            }
            'update' {
                $code = [string]$c.code
                $nv = [regex]::Match($code, '(?m)^\$AgentVersion = (\d+)').Groups[1].Value
                $errs = $null
                [void][System.Management.Automation.Language.Parser]::ParseInput($code, [ref]$null, [ref]$errs)
                if (-not $nv -or $code.Length -lt 2000 -or $errs) {
                    Send-Json $ctx 400 @{ ok = $false; msg = 'Kode agen baru tidak valid, pembaruan dibatalkan.' }; break
                }
                if (-not (Get-ScheduledTask -TaskName 'WOL Panel Agent Restart' -ErrorAction SilentlyContinue)) {
                    Send-Json $ctx 409 @{ ok = $false; msg = 'Tugas restart agen tidak ada, pasang ulang agen sekali.' }; break
                }
                Copy-Item -LiteralPath $AgentFile -Destination "$AgentFile.bak" -Force
                Set-Content -Path $AgentFile -Value $code -Encoding UTF8
                Write-Log "Diperbarui ke versi $nv oleh $script:By, memulai ulang"
                Send-Json $ctx 200 @{ ok = $true; msg = "Agen diperbarui ke versi $nv." }
                Start-ScheduledTask -TaskName 'WOL Panel Agent Restart'
            }
            default { Send-Json $ctx 400 @{ ok = $false; msg = 'Perintah tidak dikenal' } }
        }
        return
    }
    Send-Text $ctx 404 'not found'
}

while ($true) {
    $listener = $null
    try {
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("http://+:$Port/")
        $listener.Start()
        Write-Log "Agen berjalan di port $Port"
        Send-Beat
        while ($listener.IsListening) {
            $ar = $listener.BeginGetContext($null, $null)
            while (-not $ar.AsyncWaitHandle.WaitOne(30000)) { Send-Beat }
            $ctx = $listener.EndGetContext($ar)
            try { Handle $ctx } catch { Write-Log "Error: $($_.Exception.Message)"; Send-Text $ctx 500 'error' }
        }
    } catch {
        Write-Log "Listener berhenti: $($_.Exception.Message)"
    } finally {
        if ($listener) { try { $listener.Close() } catch {} }
    }
    Start-Sleep -Seconds 5
}
'@

    Write-Host 'Memasang WOL Panel Agent...'
    Stop-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue
    # proses agen lama bisa tetap hidup & memegang port; tanpa ini agen baru gagal mulai dan agen lama (kunci lama) yang menjawab
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like '*WOLPanelAgent*agent.ps1*' -and $_.ProcessId -ne $PID } |
        ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; Write-Host "    Agen lama dihentikan (PID $($_.ProcessId))" } catch {} }
    Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    # hanya SYSTEM (S-1-5-18) dan Administrators (S-1-5-32-544) yang boleh membaca kunci agen
    icacls $Dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    $File = Join-Path $Dir 'agent.ps1'
    Set-Content -Path $File -Value $AgentCode -Encoding UTF8
    Remove-Item -LiteralPath "$File.bak" -Force -ErrorAction SilentlyContinue

    $RestartCode = @'
# Dipanggil agen setelah memperbarui dirinya: mulai ulang agen, pulihkan cadangan bila agen baru tidak jalan.
$Task = 'WOL Panel Agent'
$File = Join-Path $env:ProgramData 'WOLPanelAgent\agent.ps1'
$Log  = Join-Path $env:ProgramData 'WOLPanelAgent\agent.log'
function Test-Agent { for ($i = 0; $i -lt 20; $i++) { Start-Sleep -Seconds 1
    try { if ((Invoke-WebRequest -Uri 'http://127.0.0.1:__PORT__/ping' -UseBasicParsing -TimeoutSec 2).Content -eq 'ok') { return $true } } catch {} }
    return $false }
function Restart-Agent { Stop-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like '*WOLPanelAgent*agent.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2; Start-ScheduledTask -TaskName $Task }
Start-Sleep -Seconds 2
Restart-Agent
if (-not (Test-Agent) -and (Test-Path -LiteralPath "$File.bak")) {
    Copy-Item -LiteralPath "$File.bak" -Destination $File -Force
    Add-Content -Path $Log -Value ((Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '  Agen baru gagal jalan, versi lama dipulihkan')
    Restart-Agent
}
'@
    $RestartFile = Join-Path $Dir 'restart.ps1'
    Set-Content -Path $RestartFile -Value $RestartCode -Encoding UTF8
    Unregister-ScheduledTask -TaskName "$Task Restart" -Confirm:$false -ErrorAction SilentlyContinue
    $raction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$RestartFile`""
    $rprincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName "$Task Restart" -Action $raction -Principal $rprincipal `
        -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)) `
        -Description 'Memulai ulang WOL Panel Agent setelah pembaruan otomatis' | Out-Null

    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$File`""
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries `
                   -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $Task -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description 'Agen WOL Panel: matikan, pindai aplikasi, pembaruan otomatis' | Out-Null

    Remove-NetFirewallRule -DisplayName $Rule -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName $Rule -Direction Inbound -Protocol TCP -LocalPort $Port `
        -RemoteAddress $PanelIp -Action Allow -Profile Any | Out-Null

    Start-ScheduledTask -TaskName $Task
    $ok = $false
    for ($i = 0; $i -lt 10 -and -not $ok; $i++) {
        Start-Sleep -Seconds 1
        try { $ok = ((Invoke-WebRequest -Uri "http://127.0.0.1:$Port/ping" -UseBasicParsing -TimeoutSec 2).Content -eq 'ok') } catch {}
    }
    if ($ok) {
        Write-Host "Berhasil. Agen aktif di port $Port dan hanya menerima perintah dari $PanelIp." -ForegroundColor Green
        Write-Host 'Kembali ke WOL Panel lalu klik Tes untuk memastikan panel bisa menjangkau agen.'
    } else {
        Write-Host "Agen terpasang tetapi belum menjawab. Lihat log: $Dir\agent.log" -ForegroundColor Yellow
    }
}
