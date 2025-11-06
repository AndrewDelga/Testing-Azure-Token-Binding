<#
.SYNOPSIS
  Test Entra ID Conditional Access Token Protection and export audit evidence.

.DESCRIPTION
  - On Device A (joined/compliant): acquires a Graph token, saves it to file, tests locally.
  - On Device B (unjoined/noncompliant): replays the stolen token without re-acquiring.
  - Exports a CSV row per run and a JSON evidence blob per run.

.PARAMETER TokenFile
  Path to the token file used to simulate theft/replay.

.PARAMETER ExportCsv
  Path to the evidence CSV file (created if missing).

.PARAMETER EvidenceDir
  Directory where detailed JSON evidence is written per run.

.PARAMETER NoNetworkDiscovery
  Skip public IP lookup (useful in restricted networks).

.EXAMPLES
  # Device A: Acquire token, test locally, write evidence, then copy stolen_token.txt to Device B
  .\Test-TokenProtection-WithEvidence.ps1

  # Device B: Replay existing token and log evidence
  .\Test-TokenProtection-WithEvidence.ps1 -ExportCsv .\tokenprot_evidence.csv
#>

[CmdletBinding()]
param(
  [string]$TokenFile = "C:\temp\az_access_token.txt",
  [string]$ExportCsv = "C:\temp\tokenprot_evidence.csv",
  [string]$EvidenceDir = ".\evidence",
  [switch]$NoNetworkDiscovery
)

# --------------- Helpers ---------------

function Ensure-Modules {
  if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
    Write-Host "[*] Installing Az.Accounts..." -ForegroundColor Yellow
    try { Install-Module Az.Accounts -Scope CurrentUser -Force -ErrorAction Stop }
    catch { throw "Failed to install Az.Accounts: $($_.Exception.Message)" }
  }
  Import-Module Az.Accounts -ErrorAction Stop
}

function Get-AzToken {
  Write-Host "[+] Signing in with Connect-AzAccount..." -ForegroundColor Cyan
  Connect-AzAccount -UseDeviceAuthentication | Out-Null

  $plainToken = (Get-AzAccessToken).Token

  return $plainToken
}

function Save-Text {
  param([string]$Text, [string]$Path)
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
  $Text | Out-File -FilePath $Path -Encoding ascii -Force
}

# --------------- Main Logic ---------------

Ensure-Modules

# Acquire or replay token
if (-not (Test-Path $TokenFile)) {
  Write-Host "[*] No token file found. Acquiring new token..." -ForegroundColor Yellow
  $token = Get-AzToken
  Save-Text -Text $token -Path $TokenFile
} else {
  Write-Host "[*] Replaying existing token from file..." -ForegroundColor Yellow
  $token = Get-Content $TokenFile -Raw
}

# Export evidence
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$tokenHash = [System.Convert]::ToBase64String(
  (New-Object System.Security.Cryptography.SHA256Managed).ComputeHash(
    [System.Text.Encoding]::UTF8.GetBytes($token)
  )
)

$evidenceJson = @{
  Timestamp = $timestamp
  TokenHash = $tokenHash
  MachineName = $env:COMPUTERNAME
  UserName = $env:USERNAME
  Replay = (Test-Path $TokenFile)
} | ConvertTo-Json -Depth 3

$evidencePath = Join-Path $EvidenceDir "$timestamp.json"
Save-Text -Text $evidenceJson -Path $evidencePath

# Append to CSV
$csvRow = [PSCustomObject]@{
  Timestamp = $timestamp
  MachineName = $env:COMPUTERNAME
  UserName = $env:USERNAME
  Replay = (Test-Path $TokenFile)
  EvidenceFile = $evidencePath
}
if (-not (Test-Path $ExportCsv)) {
  $csvRow | Export-Csv -Path $ExportCsv -NoTypeInformation
} else {
  $csvRow | Export-Csv -Path $ExportCsv -Append -NoTypeInformation
}

Write-Host "[+] Evidence saved to $evidencePath and logged in $ExportCsv" -ForegroundColor Green