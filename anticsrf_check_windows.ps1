<#
.SYNOPSIS
  Read-only check for Idunno.AntiCsrf (CVE-2026-131914, CVSS 9.3) on a Windows / IIS server.
  Vairav advisory VTS-SA-2026-1123-IDUNNO-ANTICSRF.
.DESCRIPTION
  Finds Idunno.AntiCsrf.dll and module references in web.config / applicationHost.config under every IIS site
  (and any extra -Path), and can hunt IIS logs for exploitation leads. No patch exists: any copy is treated as VULNERABLE.
  Makes no changes and sends no network traffic.
.PARAMETER Path      Extra folders to scan (in addition to all IIS site roots).
.PARAMETER LogPath   IIS log folder (default C:\inetpub\logs\LogFiles). Used with -HuntLogs.
.PARAMETER HuntLogs  Also hunt IIS logs.
.PARAMETER Days      Log files modified within N days (default 45).
.PARAMETER OutFile   Save a JSON report.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\anticsrf_check_windows.ps1 -HuntLogs
.NOTES
  Exit codes: 0 clean, 1 vulnerable, 2 review/leads, 3 error. Run as Administrator to read all site folders.
#>
[CmdletBinding()]
param([string[]]$Path = @(), [string]$LogPath = 'C:\inetpub\logs\LogFiles', [switch]$HuntLogs, [int]$Days = 45, [string]$OutFile)
$ErrorActionPreference = 'SilentlyContinue'
$ref = 'Idunno\.AntiCsrf|AntiCsrfModule|csrfSettings'
$cfgNames = @('web.config', 'applicationHost.config', 'machine.config')
Write-Host "`nIdunno.AntiCsrf check (CVE-2026-131914) | Vairav VTS-SA-2026-1123-IDUNNO-ANTICSRF`n"

# collect roots
$roots = New-Object System.Collections.Generic.List[string]
foreach ($p in $Path) { if ($p) { $roots.Add($p) } }
try {
    Import-Module WebAdministration -ErrorAction Stop
    Get-Website | ForEach-Object { $roots.Add([Environment]::ExpandEnvironmentVariables($_.physicalPath)) }
    Get-WebApplication | ForEach-Object { $roots.Add([Environment]::ExpandEnvironmentVariables($_.PhysicalPath)) }
} catch { Write-Host "  note: IIS WebAdministration module not available; scanning default and supplied paths only" -ForegroundColor DarkYellow }
foreach ($d in @('C:\inetpub\wwwroot')) { if (Test-Path $d) { $roots.Add($d) } }
$roots = $roots | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique
if (-not $roots) { Write-Host "No folders to scan. Use -Path." -ForegroundColor Red; exit 3 }
Write-Host ("Scanning {0} folder(s)" -f @($roots).Count)

$dlls = @(); $cfgs = @()
foreach ($r in $roots) {
    Get-ChildItem -Path $r -Recurse -Force -Filter 'Idunno.AntiCsrf.dll' -File | ForEach-Object {
        $dlls += [pscustomobject]@{ Path = $_.FullName; Version = $_.VersionInfo.FileVersion; Sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash; Size = $_.Length; Modified = $_.LastWriteTime }
    }
    Get-ChildItem -Path $r -Recurse -Force -File | Where-Object { $cfgNames -contains $_.Name.ToLower() } | ForEach-Object {
        $hit = Select-String -Path $_.FullName -Pattern $ref -SimpleMatch:$false | Select-Object -First 5
        if ($hit) { $cfgs += [pscustomobject]@{ Path = $_.FullName; Lines = ($hit | ForEach-Object { $_.Line.Trim() }) } }
    }
}
# also the machine-wide applicationHost.config and GAC
$ah = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
if (Test-Path $ah) { $h = Select-String -Path $ah -Pattern $ref | Select-Object -First 5; if ($h) { $cfgs += [pscustomobject]@{ Path = $ah; Lines = ($h | ForEach-Object { $_.Line.Trim() }) } } }
foreach ($g in @("$env:windir\Microsoft.NET\assembly", "$env:windir\assembly")) {
    Get-ChildItem -Path $g -Recurse -Force -Filter 'Idunno.AntiCsrf*.dll' -File | ForEach-Object {
        $dlls += [pscustomobject]@{ Path = $_.FullName; Version = $_.VersionInfo.FileVersion; Sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash; Size = $_.Length; Modified = $_.LastWriteTime }
    }
}

$code = 0
if ($dlls.Count -gt 0) { $verdict = 'VULNERABLE'; $why = 'Idunno.AntiCsrf.dll found: no patch exists, remove or replace the module'; $code = 1 }
elseif ($cfgs.Count -gt 0) { $verdict = 'REVIEW'; $why = 'module referenced in configuration but no DLL found in the scanned paths'; $code = 2 }
else { $verdict = 'CLEAN'; $why = 'no Idunno.AntiCsrf DLL or configuration reference found' }
$color = @{ VULNERABLE = 'Red'; REVIEW = 'Yellow'; CLEAN = 'Green' }[$verdict]
Write-Host "[$verdict] $why" -ForegroundColor $color
foreach ($d in $dlls) { Write-Host ("    DLL: {0}`n         version {1} | sha256 {2} | {3} bytes | modified {4}" -f $d.Path, $d.Version, $d.Sha256, $d.Size, $d.Modified) }
foreach ($c in $cfgs) { Write-Host "    CONFIG: $($c.Path)"; foreach ($l in $c.Lines) { Write-Host ("         " + $l.Substring(0, [Math]::Min(160, $l.Length))) } }
if ($verdict -ne 'CLEAN') { Write-Host "    Next: no patch exists. Follow advisory section 6: remove the module, replace with supported anti-forgery, then review for compromise.`n" }

$leads = @(); $longCookie = @()
if ($HuntLogs) {
    $cut = (Get-Date).AddDays(-$Days)
    $files = Get-ChildItem -Path $LogPath -Recurse -Filter *.log -File | Where-Object { $_.LastWriteTime -ge $cut }
    Write-Host ("`nIIS log hunt: {0} files" -f @($files).Count)
    foreach ($f in $files) {
        $fields = $null
        foreach ($line in [System.IO.File]::ReadLines($f.FullName)) {
            if ($line.StartsWith('#Fields:')) { $fields = $line.Substring(9).Split(' '); continue }
            if ($line.StartsWith('#') -or -not $fields) { continue }
            $row = $line.Split(' '); if ($row.Count -ne $fields.Count) { continue }
            $o = @{}; for ($i = 0; $i -lt $fields.Count; $i++) { $o[$fields[$i]] = $row[$i] }
            $uri = [string]$o['cs-uri-stem']
            if ($o['cs-method'] -eq 'POST' -and $uri -match '(?i)\.(aspx|ashx|asmx)$' -and $o['sc-status'] -in @('500', '302')) {
                $leads += [pscustomobject]@{ Ip = $o['c-ip']; Uri = $uri; Status = $o['sc-status'] }
            }
            $ck = [string]$o['cs(Cookie)']
            if ($ck -and $ck -match '(?i)(__?csrf\w*)=([A-Za-z0-9%+/=_-]{300,})') { $longCookie += [pscustomobject]@{ File = $f.Name; Date = $o['date']; Time = $o['time']; Ip = $o['c-ip']; Uri = $uri; Cookie = $Matches[1]; Length = $Matches[2].Length } }
        }
    }
    if ($longCookie.Count) { Write-Host "[LEADS] long anti-CSRF-style cookie values (300+ chars), strongest indicator:" -ForegroundColor Red; $longCookie | Select-Object -First 25 | Format-Table -AutoSize | Out-String | Write-Host; if ($code -lt 2) { $code = 2 } }
    if ($leads.Count) { Write-Host "[LEADS] POST to .aspx/.ashx/.asmx returning 500 or 302 (weak signal):" -ForegroundColor Yellow; $leads | Group-Object Ip, Uri, Status | Sort-Object Count -Descending | Select-Object -First 25 Count, Name | Format-Table -AutoSize | Out-String | Write-Host; if ($code -lt 2) { $code = 2 } }
    if (-not $longCookie.Count -and -not $leads.Count) { Write-Host "    no leads" }
    Write-Host "    Hits are leads, not proof. Enable cs(Cookie) logging in IIS to make the cookie test possible."
}
if ($OutFile) { [pscustomobject]@{ verdict = $verdict; dlls = $dlls; configs = $cfgs; longCookieLeads = $longCookie } | ConvertTo-Json -Depth 5 | Set-Content $OutFile }
exit $code
