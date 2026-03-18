# Created for cjee21/Check-UEFISecureBootVariables
# Purpose: Walk EFI binaries and warn if they match revocations via:
#   - Authenticode (WinTrust) SHA-256 hash match against microsoft/secureboot_objects dbx_info_msft_latest.json
#
# This version intentionally does NOT:
#   - compare flat/raw file SHA-256
#   - compare signer certificates
#   - use current UEFI dbx variable (CurrentDbx/Both removed)

[CmdletBinding()]
param(
    # Root directories to scan for .efi files (optional)
    [string[]] $Paths,

    # If set, will mount ESP to S: (mountvol s: /s) and scan it (default: true)
    [switch] $ScanESP = $true,

    # Helper flag: scan common OS paths too (default: false)
    [switch] $ScanDefaultPaths = $false,

    # Optional: local path to dbx_info_msft_latest.json (overrides URL if provided)
    [string] $MsftJsonPath,

    # Default: download the JSON from Microsoft secureboot_objects
    [string] $MsftJsonUrl = 'https://raw.githubusercontent.com/microsoft/secureboot_objects/refs/heads/main/PreSignedObjects/DBX/dbx_info_msft_latest.json'
)

$ErrorActionPreference = 'Stop'

Import-Module "$PSScriptRoot\Get-AuthenticodeHash.ps1" -Force

function Get-DbxAuthenticodeSetFromMsftJson {
    param(
        [string] $Path,
        [string] $Url
    )

    $jsonText = $null
    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) {
            throw "MsftJsonPath not found: $Path"
        }
        $jsonText = Get-Content -LiteralPath $Path -Raw
    } elseif ($Url) {
        $jsonText = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Content
    } else {
        throw "Provide -MsftJsonPath or -MsftJsonUrl."
    }

    $j = $jsonText | ConvertFrom-Json

    # Expected JSON structure:
    # { "images": { "x64": [ { authenticodeHash, ... }, ... ], "arm64": [ ... ] } }
    $authSet = New-Object 'System.Collections.Generic.HashSet[string]'

    foreach ($archProp in $j.images.PSObject.Properties) {
        $items = $archProp.Value
        foreach ($img in $items) {
            if ($img.authenticodeHash -and $img.authenticodeHash.Trim()) {
                [void]$authSet.Add($img.authenticodeHash.Trim().ToUpperInvariant())
            }
        }
    }

    return $authSet
}

function Get-EfiFilesUnderPaths {
    param([Parameter(Mandatory)][string[]] $RootPaths)

    $all = New-Object System.Collections.Generic.List[string]
    foreach ($root in $RootPaths) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -ieq '.efi' } |
            ForEach-Object { $all.Add($_.FullName) | Out-Null }
    }
    $all
}

# Build scan roots
$scanRoots = New-Object System.Collections.Generic.List[string]

$didMountEsp = $false
if ($ScanESP) {
    try {
        mountvol s: /s | Out-Null
        $didMountEsp = $true
        $scanRoots.Add('S:\') | Out-Null
    } catch {
        Write-Warning "Could not mount ESP to S:. Run as Administrator? Continuing..."
    }
}

if ($ScanDefaultPaths) {
    $scanRoots.Add("$env:SystemRoot\Boot\EFI") | Out-Null
    $scanRoots.Add("$env:SystemDrive\EFI") | Out-Null
    $scanRoots.Add("$env:SystemDrive\Boot") | Out-Null
}

if ($Paths) {
    foreach ($p in $Paths) { $scanRoots.Add($p) | Out-Null }
}

if ($scanRoots.Count -eq 0) {
    throw "No scan roots specified and ESP mount failed. Provide -Paths or run elevated."
}

Write-Host "Loading Microsoft DBX JSON (authenticodeHash only)..." -ForegroundColor Cyan
$authenticodeSet = Get-DbxAuthenticodeSetFromMsftJson -Path $MsftJsonPath -Url $MsftJsonUrl
Write-Host ("Loaded MsftJson: authenticodeHash count={0}" -f $authenticodeSet.Count)

Write-Host "Scanning for EFI binaries..." -ForegroundColor Cyan
$efiFiles = Get-EfiFilesUnderPaths -RootPaths $scanRoots.ToArray()
Write-Host ("Found {0} EFI file(s)." -f $efiFiles.Count)

$warnCount = 0
$idx = 0

foreach ($file in $efiFiles) {
    $idx++
    Write-Progress -Activity "Checking EFI files" -Status $file -PercentComplete (($idx / [Math]::Max(1, $efiFiles.Count)) * 100)

    $authSha = $null
    try { $authSha = Get-AuthenticodeSha256Hex -FilePath $file } catch {}

    if ($authSha -and $authenticodeSet.Contains($authSha)) {
        $warnCount++
        Write-Host ""
        Write-Host "WARNING: EFI file matches Microsoft revocation list (authenticodeHash)" -ForegroundColor Yellow
        Write-Host ("  Path: {0}" -f $file)
        Write-Host ("  SHA256 (authenticode): {0}" -f $authSha)
    }
}

Write-Host ""
Write-Host ("Scan complete. Warnings: {0}" -f $warnCount) -ForegroundColor Cyan

if ($didMountEsp) {
    try { mountvol s: /d | Out-Null } catch {}
}