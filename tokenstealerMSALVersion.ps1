<#
.SYNOPSIS
  Test Entra ID Conditional Access Token Protection and export audit evidence.

.DESCRIPTION
  - On Device A (joined/compliant): acquires a Graph token, saves it to file, tests locally.
  - On Device B (unjoined/noncompliant): replays the stolen token without re-acquiring.
  - Exports a CSV row per run and a JSON evidence blob per run.

.PARAMETER ClientId
  Public client ID to acquire user token (default uses Azure PowerShell public client).

.PARAMETER TokenFile
  Path to the token file used to simulate theft/replay.

.PARAMETER ExportCsv
  Path to the evidence CSV file (created if missing).

.PARAMETER EvidenceDir
  Directory where detailed JSON evidence is written per run.

.PARAMETER NoNetworkDiscovery
  Skip public IP lookup (useful in restricted networks).

.PARAMETER AppScope
  Resource scope to request token for (default: Graph .default).

.EXAMPLES
  # Device A: Acquire token, test locally, write evidence, then copy stolen_token.txt to Device B
  .\Test-TokenProtection-WithEvidence.ps1

  # Device B: Replay existing token and log evidence
  .\Test-TokenProtection-WithEvidence.ps1 -ExportCsv .\tokenprot_evidence.csv
#>

[CmdletBinding()]
param(
  [string]$ClientId = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", # Azure PowerShell public client
  [string]$TokenFile = ".\stolen_token.txt",
  [string]$ExportCsv = ".\tokenprot_evidence.csv",
  [string]$EvidenceDir = ".\evidence",
  [switch]$NoNetworkDiscovery,
  [string]$AppScope = "https://graph.microsoft.com/.default"
)


# --------------- Helpers ---------------

function Ensure-Modules {
  if (-not (Get-Module -ListAvailable -Name MSAL.PS)) {
    Write-Host "[*] Installing MSAL.PS..." -ForegroundColor Yellow
    try { Install-Module MSAL.PS -Scope CurrentUser -Force -ErrorAction Stop }
    catch { throw "Failed to install MSAL.PS: $($_.Exception.Message)" }
  }
  Import-Module MSAL.PS -ErrorAction Stop
}

function Get-GraphToken {
  param([string]$ClientId, [string]$Scopes, [string]$TenantId)

  $authority = "https://login.microsoftonline.com/$TenantId"
  $redirectUri = "http://localhost"

  Write-Host "[+] Requesting Graph token interactively..." -ForegroundColor Cyan
  $result = Get-MsalToken -ClientId $ClientId -Scopes $Scopes -Interactive -Authority $authority -RedirectUri $redirectUri
  if (-not $result.AccessToken) { throw "Token acquisition failed." }
  return $result.AccessToken
}



function Save-Text {
  param([string]$Text, [string]$Path)
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
  $Text | Out-File -FilePath $Path -Encoding ascii -Force
}

function Read-Text {
  param([string]$Path)
  if (-not (Test-Path $Path)) { throw "Token file not found: $Path" }
  return (Get-Content $Path -Raw)
}

function Get-DeviceJoinState {
  $state = @{
    AzureAdJoined = $null
    DeviceId      = $null
    WorkplaceJoined = $null
  }
  try {
    $out = dsregcmd /status 2>$null
    if ($LASTEXITCODE -eq 0 -and $out) {
      foreach ($line in $out) {
        if ($line -match '^\s*AzureAdJoined\s*:\s*(.+)$')   { $state.AzureAdJoined   = $Matches[1].Trim() }
        elseif ($line -match '^\s*DeviceId\s*:\s*(.+)$')    { $state.DeviceId        = $Matches[1].Trim() }
        elseif ($line -match '^\s*WorkplaceJoined\s*:\s*(.+)$') { $state.WorkplaceJoined = $Matches[1].Trim() }
      }
    }
  } catch { }
  return $state
}
function Get-PublicIP {
  param([switch]$Skip)
  if ($Skip) { return $null }
  try {
    $r = Invoke-RestMethod -Uri "https://api.ipify.org?format=json" -TimeoutSec 5 -ErrorAction Stop
    return $r.ip
  } catch { return $null }
}

function Safe-JwtDecode {
  param([string]$Jwt)
  # Extract payload without validation (evidence only)
  try {
    $parts = $Jwt.Split('.')
    if ($parts.Count -lt 2) { return $null }
    $padded = $parts[1] + '=' * ((4 - $parts[1].Length % 4) % 4)
    $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($padded.Replace('-','+').Replace('_','/')))
    return $json | ConvertFrom-Json
  } catch { return $null }
}

function Get-Sha256Base64 {
  param([string]$Text)
  try {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    return [Convert]::ToBase64String($sha.ComputeHash($bytes))
  } catch { return $null }
}

function Invoke-GraphMe {
  param([string]$Token)
  $headers = @{ Authorization = "Bearer $Token" }
  $uri = "https://graph.microsoft.com/v1.0/me"
  $result = @{
    Success          = $false
    StatusCode       = $null
    CorrelationId    = $null
    ResponseBody     = $null
    ErrorMessage     = $null
    RawHeaders       = @{}
  }
  try {
    $resp = Invoke-WebRequest -Method GET -Uri $uri -Headers $headers -ErrorAction Stop
    $result.Success = $true
    $result.StatusCode = $resp.StatusCode.value__
    $result.ResponseBody = if ($resp.Content) { ($resp.Content | ConvertFrom-Json) } else { $null }
    foreach ($k in $resp.Headers.Keys) { $result.RawHeaders[$k] = $resp.Headers[$k] -join "," }
    if ($result.RawHeaders['request-id']) { $result.CorrelationId = $result.RawHeaders['request-id'] }
  } catch {
    $ex = $_.Exception
    $result.ErrorMessage = $ex.Message
    if ($ex.Response) {
      try {
        $result.StatusCode = $ex.Response.StatusCode.value__
        # grab headers
        $hdrs = $ex.Response.Headers
        foreach ($k in $hdrs.Keys) { $result.RawHeaders[$k] = $hdrs[$k] -join "," }
        if ($result.RawHeaders['request-id']) { $result.CorrelationId = $result.RawHeaders['request-id'] }
        # body
        $sr = New-Object System.IO.StreamReader($ex.Response.GetResponseStream())
        $bodyText = $sr.ReadToEnd()
        if ($bodyText) {
          try { $result.ResponseBody = $bodyText | ConvertFrom-Json } catch { $result.ResponseBody = $bodyText }
        }
      } catch { }
    }
  }
  return $result
}

function Write-CsvRow {
  param([hashtable]$Row, [string]$CsvPath)
  $exists = Test-Path $CsvPath
  $obj = [PSCustomObject]$Row
  if ($exists) {
    $obj | Export-Csv -Path $CsvPath -NoTypeInformation -Append -Encoding UTF8
  } else {
    $obj | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
  }
}

function Write-EvidenceJson {
  param([hashtable]$Evidence, [string]$Dir, [string]$TestId)
  if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir | Out-Null }
  $path = Join-Path $Dir ("evidence_" + $TestId + ".json")
  ($Evidence | ConvertTo-Json -Depth 6) | Out-File -FilePath $path -Encoding UTF8
  return $path
}








# --------------- Main ---------------

$utcNow = (Get-Date).ToUniversalTime().ToString("s") + "Z"
$testId = [Guid]::NewGuid().ToString()
$machine = $env:COMPUTERNAME
$os = (Get-CimInstance Win32_OperatingSystem).Caption + " " + (Get-CimInstance Win32_OperatingSystem).Version
$join = Get-DeviceJoinState
$publicIp = Get-PublicIP -Skip:$NoNetworkDiscovery

$mode = if (Test-Path $TokenFile) { "ReplayOnly (DeviceB?)" } else { "AcquireAndTest (DeviceA)" }

Write-Host "[*] TestId: $testId" -ForegroundColor DarkCyan
Write-Host "[*] Mode: $mode"
Write-Host "[*] Machine: $machine | OS: $os"
Write-Host "[*] AzureAdJoined: $($join.AzureAdJoined) | DeviceId: $($join.DeviceId)"
if ($publicIp) { Write-Host "[*] Public IP: $publicIp" }

# Acquire or read token
$token = $null
if ($mode -eq "AcquireAndTest (DeviceA)") {
  Ensure-Modules
  $TenantId = "af7e785b-7f5b-4275-a075-a4a22d1f382a"  # or your actual tenant GUID
  $token = Get-GraphToken -ClientId $ClientId -Scopes $AppScope -TenantId $TenantId
  Save-Text -Text $token -Path $TokenFile
  Write-Host "[+] Saved token to $TokenFile (copy this to Device B to simulate theft)" -ForegroundColor Green
} else {
  $token = Read-Text -Path $TokenFile
}

# Token fingerprint & claims (safe)
$tokenHash = Get-Sha256Base64 -Text $token
$claims = Safe-JwtDecode -Jwt $token
$upn = if ($claims.upn) { $claims.upn } else { $claims.preferred_username }
$tid = $claims.tid
$oid = $claims.oid
$cnf = $claims.cnf # device binding info if present

# Attempt to call Graph
$result = Invoke-GraphMe -Token $token

# Outcome
$outcome = if ($result.Success) { "Success" } else { "Failure" }
$hint =
  if ($result.Success) {
    "Token accepted on this device."
  } else {
    "Rejected (HTTP $($result.StatusCode)). If this device is not the issuing device, Token Protection likely blocked replay."
  }


# Build CSV row
$row = @{
  TimestampUTC           = $utcNow
  TestId                 = $testId
  Mode                   = $mode
  MachineName            = $machine
  OSVersion              = $os
  AzureAdJoined          = $join.AzureAdJoined
  DeviceId               = $join.DeviceId
  PublicIP               = $publicIp
  UserPrincipalName      = $upn
  TenantId               = $tid
  ObjectId               = $oid
  TokenHash_SHA256_Base64= $tokenHash
  TokenHasCnf            = [bool]($cnf)
  TargetResource         = "https://graph.microsoft.com/v1.0/me"
  Outcome                = $outcome
  HttpStatus             = $result.StatusCode
  CorrelationId          = $result.CorrelationId
  ErrorMessage           = $result.ErrorMessage
}

# Write CSV + JSON evidence
Write-CsvRow -Row $row -CsvPath $ExportCsv | Out-Null
$evidence = @{
  Meta = $row
  Raw = @{
    Claims = $claims
    ResponseBody = $result.ResponseBody
    Headers = $result.RawHeaders
  }
}
$evidencePath = Write-EvidenceJson -Evidence $evidence -Dir $EvidenceDir -TestId $testId

Write-Host ""
Write-Host "=== RESULT ===" -ForegroundColor White
Write-Host ("Outcome: " + $outcome) -ForegroundColor ($(if($outcome -eq 'Success'){'Green'}else{'Yellow'}))
Write-Host ("HTTP Status: " + $result.StatusCode)
if ($result.CorrelationId) { Write-Host ("CorrelationId: " + $result.CorrelationId) }
Write-Host ("Hint: " + $hint)
Write-Host ""
Write-Host ("CSV: " + (Resolve-Path $ExportCsv))
Write-Host ("Evidence JSON: " + (Resolve-Path $evidencePath))
#>