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
$Log     = Join-Path (Join-Path $env:ProgramData 'WOLPanelAgent') 'agent.log'
$Seen    = @{}

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

function Handle($ctx) {
    $req  = $ctx.Request
    $from = $req.RemoteEndPoint.Address.ToString()
    $path = $req.Url.AbsolutePath

    if ($req.HttpMethod -eq 'GET' -and $path -eq '/ping') {
        if ($from -eq $PanelIp -or $from -eq '127.0.0.1' -or $from -eq '::1') { Send-Text $ctx 200 'ok' }
        else { Send-Text $ctx 403 'forbidden' }
        return
    }
    if ($from -ne $PanelIp) { Send-Text $ctx 403 'forbidden'; Write-Log "Ditolak dari $from (bukan IP panel)"; return }
    if ($req.HttpMethod -ne 'POST' -or $path -ne '/shutdown') { Send-Text $ctx 404 'not found'; return }

    $ts    = [string]$req.Headers['X-WOL-Time']
    $nonce = [string]$req.Headers['X-WOL-Nonce']
    $delay = [string]$req.Headers['X-WOL-Delay']
    $by    = [string]$req.Headers['X-WOL-User']
    $sig   = [string]$req.Headers['X-WOL-Signature']

    if ($ts -notmatch '^\d{9,11}$' -or $nonce -notmatch '^[0-9a-f]{16,64}$' -or
        $delay -notmatch '^\d{1,3}$' -or $by -notmatch '^[A-Za-z0-9._-]{0,32}$' -or $sig -notmatch '^[0-9a-f]{64}$') {
        Send-Text $ctx 400 'bad request'; return
    }
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if ([Math]::Abs($now - [long]$ts) -gt 120) { Send-Text $ctx 401 'clock'; Write-Log 'Ditolak: selisih jam panel dan komputer lebih dari 2 menit'; return }
    if (-not (Test-Same (Get-Sig "shutdown|$ts|$nonce|$delay|$by") $sig)) { Send-Text $ctx 401 'unauthorized'; Write-Log 'Ditolak: tanda tangan tidak cocok'; return }
    if ($Seen.ContainsKey($nonce)) { Send-Text $ctx 401 'replay'; return }

    foreach ($k in @($Seen.Keys)) { if ($now - $Seen[$k] -gt 300) { $Seen.Remove($k) } }
    $Seen[$nonce] = $now

    $d = [Math]::Min([int]$delay, 600)
    Send-Text $ctx 200 'ok'
    Write-Log "Matikan dalam $d detik, diminta oleh $by"
    & "$env:SystemRoot\System32\shutdown.exe" /s /f /t $d /c "Komputer dimatikan dari WOL Panel oleh $by" | Out-Null
}

while ($true) {
    $listener = $null
    try {
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("http://+:$Port/")
        $listener.Start()
        Write-Log "Agen berjalan di port $Port"
        while ($listener.IsListening) {
            $ctx = $listener.GetContext()
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
    Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    # hanya SYSTEM (S-1-5-18) dan Administrators (S-1-5-32-544) yang boleh membaca kunci agen
    icacls $Dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    $File = Join-Path $Dir 'agent.ps1'
    Set-Content -Path $File -Value $AgentCode -Encoding UTF8

    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$File`""
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries `
                   -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $Task -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description 'Menerima perintah matikan dari WOL Panel' | Out-Null

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
