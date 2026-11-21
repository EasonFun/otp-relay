#requires -Version 5.1
<#
  OTP Assistant - receives SMS forwarded by phone over LAN,
  extracts the verification code, copies it to the clipboard
  and shows a notification.

  All user-visible Chinese text is loaded from strings.json / ui.html
  so that this file stays pure ASCII (PowerShell 5.1 safe).

  Endpoints
    POST /sms        body = raw sms text or json {from,content}
    GET  /sms?...    same, query string form
    GET  /           web dashboard
    GET  /api/latest , /api/history , /api/status , /health
#>
param(
    [int]$Port = 0,
    [switch]$ConsoleMode
)

$ErrorActionPreference = 'Continue'

$ScriptRoot = $PSScriptRoot
if (-not $ScriptRoot) { $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition }

$DataDir = Join-Path $ScriptRoot 'data'
$LogDir = Join-Path $ScriptRoot 'logs'
foreach ($d in @($DataDir, $LogDir)) {
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
$LogFile = Join-Path $LogDir 'otp.log'
$HistoryFile = Join-Path $DataDir 'history.json'

function Write-Log {
    param([string]$Message)
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    try {
        if ((Test-Path -LiteralPath $LogFile) -and ((Get-Item -LiteralPath $LogFile).Length -gt 2MB)) {
            Move-Item -LiteralPath $LogFile -Destination ($LogFile + '.old') -Force
        }
    } catch { }
    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 } catch { }
    if ($ConsoleMode) { Write-Host $line }
}

function Read-JsonFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try { return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}

# ---------- configuration ----------

$Config = Read-JsonFile (Join-Path $ScriptRoot 'config.json')
if (-not $Config) { $Config = [pscustomobject]@{} }
$Strings = Read-JsonFile (Join-Path $ScriptRoot 'strings.json')
if (-not $Strings) { $Strings = [pscustomobject]@{} }

function Get-Cfg {
    param([string]$Name, $Default)
    if ($Config.PSObject.Properties.Name -contains $Name) { return $Config.$Name }
    return $Default
}

if ($Port -le 0) { $Port = [int](Get-Cfg 'port' 8788) }
$AutoCopy = [bool](Get-Cfg 'autoCopyOnReceive' $true)
$AutoPaste = [bool](Get-Cfg 'autoPasteAfterHotkey' $true)
$KeepHistory = [int](Get-Cfg 'keepHistory' 100)
$KeywordPattern = [string](Get-Cfg 'keywordPattern' 'verification code|security code|OTP|code')

function Get-String {
    param([string]$Name, [string]$Default)
    if ($Strings.PSObject.Properties.Name -contains $Name) { return [string]$Strings.$Name }
    return $Default
}

$AppName = Get-String 'appName' 'OTP Assistant'

# ---------- state ----------

$script:Latest = $null
$script:LastRaw = ''
$script:History = New-Object System.Collections.ArrayList

if (Test-Path -LiteralPath $HistoryFile) {
    try {
        $loaded = Get-Content -LiteralPath $HistoryFile -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($item in @($loaded)) {
            if ($item -and $item.id) { [void]$script:History.Add($item) }
        }
    } catch { }
}

function Save-History {
    try {
        @($script:History | Select-Object -First $KeepHistory) | ConvertTo-Json -Depth 6 -Compress | Set-Content -LiteralPath $HistoryFile -Encoding UTF8
    } catch { }
}

# ---------- code extraction ----------

function Get-OtpCandidates {
    param([string]$Text)
    $list = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrEmpty($Text)) { return $list }

    if ($KeywordPattern) {
        try {
            $re = New-Object System.Text.RegularExpressions.Regex("(?:$KeywordPattern)[^0-9]{0,24}([0-9]{4,8})", 'IgnoreCase')
            foreach ($m in $re.Matches($Text)) {
                [void]$list.Add([pscustomobject]@{ Code = $m.Groups[1].Value; Score = 100 })
            }
        } catch { }
    }

    $re2 = New-Object System.Text.RegularExpressions.Regex('(?<![0-9])([0-9]{4,8})(?![0-9])')
    foreach ($m in $re2.Matches($Text)) {
        $code = $m.Groups[1].Value
        $score = 40
        switch ($code.Length) {
            6 { $score = 70 }
            4 { $score = 55 }
            8 { $score = 60 }
            5 { $score = 50 }
            7 { $score = 50 }
        }
        $leftStart = [Math]::Max(0, $m.Index - 8)
        $left = $Text.Substring($leftStart, $m.Index - $leftStart)
        $rightLen = [Math]::Min(10, $Text.Length - ($m.Index + $m.Length))
        $right = ''
        if ($rightLen -gt 0) { $right = $Text.Substring($m.Index + $m.Length, $rightLen) }

        # money / units / dates / phone-like context are almost never the code
        if ($left -match '\uFFE5|\u00A5|\$|\u5143|\u6298|\u4E07|\u514B|\u5143') { $score -= 45 }
        if ($right -match '^\s*(\u5143|\u5757|\u4E07|GB|MB|M|G|KB|\u79EF\u5206|\u5929|\u5C0F\u65F6|\u5206\u949F|\u79D2|\u5E74|\u6708|\u65E5|\u4E2A|\u6B21|\u5F20|\u4EF6)') { $score -= 45 }
        if ($right -match '^\s*(-|\u5E74|\u6708|\u65E5|:)') { $score -= 40 }
        if ($left -match '(\u59D3\u540D|ID|\u8BA2\u5355|\u7F16\u53F7|\u5361\u53F7|\u5E10\u53F7|\u624B\u673A|\u7535\u8BDD|No\.?|\u5E8F\u53F7|\u5DE5\u5355)\s*[:#]?\s*$') { $score -= 35 }
        if ($code -match '^(19|20)[0-9]{2}$') { $score -= 30 }
        if ($code -match '^(0+|1+|8+|6+)$') { $score -= 25 }
        [void]$list.Add([pscustomobject]@{ Code = $code; Score = $score })
    }
    return $list
}

function Select-BestCode {
    param($Candidates)
    $best = $null
    foreach ($c in $Candidates) {
        if ($null -eq $best -or $c.Score -gt $best.Score) { $best = $c }
    }
    if ($best -and $best.Score -ge 45) { return $best.Code }
    return ''
}

function Get-SmsFields {
    param([string]$Raw)
    $from = ''
    $content = $Raw
    $trim = $Raw.Trim()
    if ($trim.StartsWith('{') -or $trim.StartsWith('[')) {
        try {
            $obj = $trim | ConvertFrom-Json
            if ($obj -is [array]) { $obj = $obj[0] }
            $props = @($obj.PSObject.Properties.Name)
            foreach ($k in @('from', 'sender', 'phone', 'address', 'mobile', 'number', 'senderName')) {
                if ($props -contains $k -and $obj.$k) { $from = [string]$obj.$k; break }
            }
            foreach ($k in @('content', 'msg', 'message', 'text', 'body', 'sms', 'smsContent')) {
                if ($props -contains $k -and $obj.$k) { $content = [string]$obj.$k; break }
            }
        } catch { }
    }
    return [pscustomobject]@{ From = $from; Content = $content }
}

# ---------- clipboard / notification ----------

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
try { Add-Type -AssemblyName System.Web } catch { }

$script:Notify = $null
try {
    $script:Notify = New-Object System.Windows.Forms.NotifyIcon
    $script:Notify.Icon = [System.Drawing.SystemIcons]::Information
    $script:Notify.Text = $AppName
    $script:Notify.Visible = $true
} catch { }

function Set-Clip {
    param([string]$Text)
    for ($i = 0; $i -lt 4; $i++) {
        try {
            Set-Clipboard -Value $Text -ErrorAction Stop
            return $true
        } catch {
            Start-Sleep -Milliseconds 200
        }
    }
    return $false
}

function Show-Toast {
    param([string]$Title, [string]$Body)
    try { [System.Media.SystemSounds]::Asterisk.Play() } catch { }
    if ($script:Notify) {
        try {
            $script:Notify.ShowBalloonTip(6000, $Title, $Body, [System.Windows.Forms.ToolTipIcon]::Info)
            return
        } catch { }
    }
    if ($ConsoleMode) { Write-Host "[toast] $Title - $Body" }
}

# ---------- hotkey ----------

$hotkeyOk = $false
try {
    Add-Type -Namespace OtpNative -Name Keys -MemberDefinition @'
[DllImport("user32.dll")] public static extern short GetAsyncKeyState(int vKey);
'@
    $hotkeyOk = $true
} catch { }

$script:HotDown = $false
$script:HotLast = [DateTime]::MinValue

function Test-HotkeyDown {
    $ctrl = ([OtpNative.Keys]::GetAsyncKeyState(0x11) -band 0x8000) -ne 0
    if (-not $ctrl) { return $false }
    $alt = ([OtpNative.Keys]::GetAsyncKeyState(0x12) -band 0x8000) -ne 0
    if (-not $alt) { return $false }
    return (([OtpNative.Keys]::GetAsyncKeyState(0x56) -band 0x8000) -ne 0)
}

# ---------- sms handling ----------

function Add-Sms {
    param([string]$Raw, [string]$Remote)

    $fields = Get-SmsFields $Raw
    $candidates = Get-OtpCandidates $fields.Content
    $code = Select-BestCode $candidates

    $now = Get-Date
    $rec = [pscustomobject]@{
        id      = [guid]::NewGuid().ToString('N').Substring(0, 8)
        time    = $now.ToString('yyyy-MM-dd HH:mm:ss')
        from    = $fields.From
        code    = $code
        content = $fields.Content
        raw     = $Raw
        remote  = $Remote
    }

    $script:Latest = $rec
    $script:LastRaw = $Raw
    $script:History.Insert(0, $rec)
    while ($script:History.Count -gt $KeepHistory) { $script:History.RemoveAt($script:History.Count - 1) }
    Save-History

    $copied = $false
    if ($code -and $AutoCopy) { $copied = Set-Clip $code }

    $title = (Get-String 'toastTitle' 'Code') + ' ' + $(if ($code) { $code } else { '?' })
    $body = if ($code) {
        (Get-String 'toastCopied' 'Copied') + "`n" + $fields.From
    } else {
        (Get-String 'toastNoCode' 'No code found') + "`n" + $fields.From
    }
    $preview = $fields.Content
    if ($preview.Length -gt 120) { $preview = $preview.Substring(0, 120) + '...' }
    Show-Toast $title ($body.Trim() + "`n" + $preview)

    Write-Log ("SMS from='" + $fields.From + "' code='" + $code + "' copied=" + $copied + " remote=" + $Remote)
    return $rec
}

# ---------- http helpers ----------

function Try-ParseChunked {
    param([byte[]]$Data)
    $out = New-Object System.IO.MemoryStream
    $pos = 0
    while ($true) {
        $lineEnd = -1
        for ($i = $pos; $i -lt $Data.Length - 1; $i++) {
            if ($Data[$i] -eq 13 -and $Data[$i + 1] -eq 10) { $lineEnd = $i; break }
        }
        if ($lineEnd -lt 0) { return @{ Done = $false; Body = $null } }
        $sizeLine = [System.Text.Encoding]::ASCII.GetString($Data, $pos, $lineEnd - $pos)
        $sizeLine = ($sizeLine -split ';')[0].Trim()
        $size = 0
        if (-not [int]::TryParse($sizeLine, [System.Globalization.NumberStyles]::HexNumber, $null, [ref]$size)) {
            return @{ Done = $false; Body = $null }
        }
        $pos = $lineEnd + 2
        if ($size -eq 0) { return @{ Done = $true; Body = $out.ToArray() } }
        if ($pos + $size -gt $Data.Length) { return @{ Done = $false; Body = $null } }
        $out.Write($Data, $pos, $size)
        $pos += $size + 2
    }
}

function Read-Request {
    param($Stream)
    $buf = New-Object byte[] 8192
    $ms = New-Object System.IO.MemoryStream
    $headerEnd = -1
    $data = $null

    while ($true) {
        $n = $Stream.Read($buf, 0, $buf.Length)
        if ($n -le 0) { break }
        $ms.Write($buf, 0, $n)
        $data = $ms.ToArray()
        for ($i = 3; $i -lt $data.Length; $i++) {
            if ($data[$i - 3] -eq 13 -and $data[$i - 2] -eq 10 -and $data[$i - 1] -eq 13 -and $data[$i] -eq 10) {
                $headerEnd = $i - 3
                break
            }
        }
        if ($headerEnd -ge 0 -or $data.Length -gt 131072) { break }
    }
    if ($headerEnd -lt 0) { return $null }

    $head = [System.Text.Encoding]::ASCII.GetString($data, 0, $headerEnd)
    $lines = $head -split "`r`n"
    $parts = $lines[0] -split ' '
    $method = 'GET'
    $path = '/'
    if ($parts.Length -ge 1) { $method = $parts[0].ToUpperInvariant() }
    if ($parts.Length -ge 2) { $path = $parts[1] }

    $headers = @{}
    for ($i = 1; $i -lt $lines.Length; $i++) {
        $idx = $lines[$i].IndexOf(':')
        if ($idx -gt 0) {
            $headers[$lines[$i].Substring(0, $idx).Trim().ToLowerInvariant()] = $lines[$i].Substring($idx + 1).Trim()
        }
    }

    $body = New-Object System.IO.MemoryStream
    $start = $headerEnd + 4
    if ($data.Length -gt $start) { $body.Write($data, $start, $data.Length - $start) }

    $te = ''
    if ($headers.ContainsKey('transfer-encoding')) { $te = $headers['transfer-encoding'].ToLowerInvariant() }
    if ($te.Contains('chunked')) {
        $all = $body.ToArray()
        while ($true) {
            $parsed = Try-ParseChunked -Data $all
            if ($parsed.Done) {
                return @{ Method = $method; Path = $path; Headers = $headers; Body = $parsed.Body }
            }
            $n = $Stream.Read($buf, 0, $buf.Length)
            if ($n -le 0) { break }
            $tmp = New-Object System.IO.MemoryStream
            $tmp.Write($all, 0, $all.Length)
            $tmp.Write($buf, 0, $n)
            $all = $tmp.ToArray()
        }
        return @{ Method = $method; Path = $path; Headers = $headers; Body = $all }
    }

    $cl = 0
    if ($headers.ContainsKey('content-length')) { [void][int]::TryParse($headers['content-length'], [ref]$cl) }
    while ($body.Length -lt $cl) {
        $n = $Stream.Read($buf, 0, $buf.Length)
        if ($n -le 0) { break }
        $body.Write($buf, 0, $n)
    }
    return @{ Method = $method; Path = $path; Headers = $headers; Body = $body.ToArray() }
}

function Send-Response {
    param($Stream, [int]$Status, [string]$ContentType, [byte[]]$Bytes)
    $reason = 'OK'
    switch ($Status) {
        204 { $reason = 'No Content' }
        400 { $reason = 'Bad Request' }
        404 { $reason = 'Not Found' }
        500 { $reason = 'Internal Server Error' }
    }
    if ($null -eq $Bytes) { $Bytes = New-Object byte[] 0 }
    $head = "HTTP/1.1 $Status $reason`r`nContent-Type: $ContentType`r`nContent-Length: $($Bytes.Length)`r`nCache-Control: no-store`r`nConnection: close`r`n`r`n"
    $hb = [System.Text.Encoding]::ASCII.GetBytes($head)
    try {
        $Stream.Write($hb, 0, $hb.Length)
        if ($Bytes.Length -gt 0) { $Stream.Write($Bytes, 0, $Bytes.Length) }
        $Stream.Flush()
    } catch { }
}

function Get-LocalIps {
    $ips = New-Object System.Collections.ArrayList
    try {
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne 'Up') { continue }
            if ($nic.NetworkInterfaceType -eq 'Loopback') { continue }
            foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
                if ($ua.Address.AddressFamily -eq 'InterNetwork') { [void]$ips.Add($ua.Address.IPAddressToString) }
            }
        }
    } catch { }
    return @($ips)
}

function Send-Json {
    param($Stream, $Object)
    $json = $Object | ConvertTo-Json -Depth 6 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    Send-Response -Stream $Stream -Status 200 -ContentType 'application/json; charset=utf-8' -Bytes $bytes
}

function Get-QueryParam {
    param([string]$Path, [string]$Name)
    $q = $Path.IndexOf('?')
    if ($q -lt 0) { return $null }
    $qs = $Path.Substring($q + 1)
    foreach ($pair in $qs.Split('&')) {
        $kv = $pair.Split('=', 2)
        if ($kv.Length -eq 2 -and $kv[0] -eq $Name) {
            return [System.Uri]::UnescapeDataString($kv[1].Replace('+', ' '))
        }
    }
    return $null
}

function Decode-Body {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return '' }
    $text = [System.Text.Encoding]::UTF8.GetString($Bytes)
    if ($text.IndexOf([char]0xFFFD) -ge 0) {
        try { $text = [System.Text.Encoding]::GetEncoding('GB18030').GetString($Bytes) } catch { }
    }
    return $text
}

# ---------- main ----------

$listener = $null
try {
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $Port)
    $listener.Start()
} catch {
    Write-Log ('cannot listen on port ' + $Port + ': ' + $_.Exception.Message)
    if ($ConsoleMode) { Write-Host ('cannot listen on port ' + $Port) }
    exit 1
}

$ips = (Get-LocalIps) -join ', '
Write-Log ('started on port ' + $Port + ' | ips: ' + $ips)
if ($ConsoleMode) {
    Write-Host ''
    Write-Host ('  ' + $AppName + '  running on port ' + $Port)
    foreach ($ip in (Get-LocalIps)) { Write-Host ('  http://' + $ip + ':' + $Port + '/sms') }
    Write-Host '  Ctrl+C to stop'
    Write-Host ''
}

$uiPath = Join-Path $ScriptRoot 'ui.html'

try {
    while ($true) {
        if ($listener.Pending()) {
            $client = $listener.AcceptTcpClient()
            try {
                $client.NoDelay = $true
                $stream = $client.GetStream()
                $stream.ReadTimeout = 8000
                $stream.WriteTimeout = 8000

                $req = Read-Request -Stream $stream
                if ($req) {
                    $path = $req.Path
                    $pathOnly = $path
                    $qIdx = $pathOnly.IndexOf('?')
                    if ($qIdx -ge 0) { $pathOnly = $pathOnly.Substring(0, $qIdx) }
                    $remote = ''
                    try { $remote = $client.Client.RemoteEndPoint.Address.IPAddressToString } catch { }
                    if ($remote -ne '127.0.0.1' -or $req.Method -ne 'GET') {
                        Write-Log ('REQ ' + $req.Method + ' ' + $pathOnly + ' from ' + $remote)
                    }

                    if ($req.Method -eq 'POST') {
                        $bodyText = Decode-Body -Bytes $req.Body
                        $ct = ''
                        if ($req.Headers.ContainsKey('content-type')) { $ct = $req.Headers['content-type'].ToLowerInvariant() }
                        if ($ct.Contains('urlencoded') -and $bodyText) {
                            try {
                                $nv = [System.Web.HttpUtility]::ParseQueryString($bodyText)
                                $fldContent = ''
                                foreach ($k in @('content', 'msg', 'message', 'text', 'body', 'sms')) {
                                    if ($nv[$k]) { $fldContent = $nv[$k]; break }
                                }
                                if ($fldContent) {
                                    $fldFrom = ''
                                    foreach ($k in @('from', 'sender', 'phone', 'address', 'mobile', 'number')) {
                                        if ($nv[$k]) { $fldFrom = $nv[$k]; break }
                                    }
                                    $bodyText = ([pscustomobject]@{ from = $fldFrom; content = $fldContent } | ConvertTo-Json -Compress)
                                }
                            } catch { }
                        }
                        if ([string]::IsNullOrWhiteSpace($bodyText)) {
                            $bodyText = [string](Get-QueryParam -Path $path -Name 'content')
                            if (-not $bodyText) { $bodyText = [string](Get-QueryParam -Path $path -Name 'msg') }
                        }
                        $rec = Add-Sms -Raw $bodyText -Remote $remote
                        Send-Json -Stream $stream -Object ([pscustomobject]@{ ok = $true; code = $rec.code; from = $rec.from })
                    }
                    elseif ($req.Method -eq 'GET') {
                        switch ($pathOnly) {
                            '/' {
                                if (Test-Path -LiteralPath $uiPath) {
                                    $bytes = [System.IO.File]::ReadAllBytes($uiPath)
                                    Send-Response -Stream $stream -Status 200 -ContentType 'text/html; charset=utf-8' -Bytes $bytes
                                } else {
                                    Send-Response -Stream $stream -Status 404 -ContentType 'text/plain; charset=utf-8' -Bytes ([System.Text.Encoding]::UTF8.GetBytes('ui.html missing'))
                                }
                            }
                            '/favicon.ico' {
                                Send-Response -Stream $stream -Status 204 -ContentType 'image/x-icon' -Bytes (New-Object byte[] 0)
                            }
                            '/health' {
                                $bytes = [System.Text.Encoding]::UTF8.GetBytes('ok')
                                Send-Response -Stream $stream -Status 200 -ContentType 'text/plain; charset=utf-8' -Bytes $bytes
                            }
                            '/sms' {
                                $c = [string](Get-QueryParam -Path $path -Name 'content')
                                if (-not $c) { $c = [string](Get-QueryParam -Path $path -Name 'msg') }
                                if (-not $c) { $c = [string](Get-QueryParam -Path $path -Name 'text') }
                                if (-not $c) { $c = $path }
                                $f = [string](Get-QueryParam -Path $path -Name 'from')
                                $raw = $c
                                if ($f) { $raw = '{"from":"' + $f.Replace('"', '') + '","content":"' + $c.Replace('"', '') + '"}' }
                                $rec = Add-Sms -Raw $raw -Remote $remote
                                Send-Json -Stream $stream -Object ([pscustomobject]@{ ok = $true; code = $rec.code; from = $rec.from })
                            }
                            '/api/latest' {
                                if ($script:Latest) { Send-Json -Stream $stream -Object $script:Latest }
                                else { Send-Json -Stream $stream -Object ([pscustomobject]@{ empty = $true }) }
                            }
                            '/api/history' {
                                Send-Json -Stream $stream -Object ([pscustomobject]@{ items = @($script:History | Select-Object -First 30) })
                            }
                            '/api/status' {
                                Send-Json -Stream $stream -Object ([pscustomobject]@{
                                        port      = $Port
                                        ips       = @(Get-LocalIps)
                                        autoCopy  = $AutoCopy
                                        autoPaste = $AutoPaste
                                        count     = $script:History.Count
                                        lastRaw   = $script:LastRaw
                                        started   = $true
                                    })
                            }
                            default {
                                Send-Response -Stream $stream -Status 404 -ContentType 'text/plain; charset=utf-8' -Bytes ([System.Text.Encoding]::UTF8.GetBytes('not found'))
                            }
                        }
                    }
                    else {
                        Send-Response -Stream $stream -Status 400 -ContentType 'text/plain' -Bytes ([System.Text.Encoding]::UTF8.GetBytes('bad request'))
                    }
                }
            } catch {
                Write-Log ('request error: ' + $_.Exception.Message)
            } finally {
                try { $client.Close() } catch { }
            }
        }

        if ($hotkeyOk) {
            $down = Test-HotkeyDown
            if ($down) {
                $elapsed = ((Get-Date) - $script:HotLast).TotalMilliseconds
                if (-not $script:HotDown -and $elapsed -gt 900) {
                    $script:HotLast = Get-Date
                    if ($script:Latest -and $script:Latest.code) {
                        $ok = Set-Clip $script:Latest.code
                        Show-Toast ((Get-String 'toastTitle' 'Code') + ' ' + $script:Latest.code) (Get-String 'toastHotkey' 'copied')
                        if ($AutoPaste -and $ok) {
                            Start-Sleep -Milliseconds 180
                            try { [System.Windows.Forms.SendKeys]::SendWait('^v') } catch { }
                        }
                    } else {
                        Show-Toast (Get-String 'toastTitle' 'Code') (Get-String 'toastNoHistory' 'no code yet')
                    }
                }
                $script:HotDown = $true
            } else {
                $script:HotDown = $false
            }
        }

        Start-Sleep -Milliseconds 40
    }
} finally {
    try { if ($listener) { $listener.Stop() } } catch { }
    try { if ($script:Notify) { $script:Notify.Visible = $false; $script:Notify.Dispose() } } catch { }
    Write-Log 'stopped'
}
