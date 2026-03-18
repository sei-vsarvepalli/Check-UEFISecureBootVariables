# Computes the Authenticode (WinTrust) SHA-256 hash for a PE image.
# This is the digest used by Authenticode signature verification, not a flat file hash.
#
# Key rules (high level):
#  - The OptionalHeader CheckSum field is treated as 0
#  - The Security Directory (Certificate Table) data directory entry is treated as 0
#  - The WIN_CERTIFICATE blob (the certificate table) is excluded from hashing
#
# Returns: uppercase hex SHA-256 string

function Get-AuthenticodeSha256Hex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $FilePath
    )

    if (-not (Test-Path -LiteralPath $FilePath)) {
        throw "File not found: $FilePath"
    }

    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    if ($bytes.Length -lt 0x100) {
        throw "File too small to be a PE: $FilePath"
    }

    # DOS header e_lfanew @ 0x3C
    $peOffset = [BitConverter]::ToUInt32($bytes, 0x3C)
    if ($peOffset -ge $bytes.Length - 4) {
        throw "Invalid PE offset: $FilePath"
    }

    # PE signature "PE\0\0"
    if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset+1] -ne 0x45 -or $bytes[$peOffset+2] -ne 0x00 -or $bytes[$peOffset+3] -ne 0x00) {
        throw "Missing PE signature: $FilePath"
    }

    # Optional header starts after: 4 (sig) + 20 (COFF)
    $optionalHeaderOffset = $peOffset + 4 + 20
    if ($optionalHeaderOffset -ge $bytes.Length) {
        throw "Invalid optional header offset: $FilePath"
    }

    $magic = [BitConverter]::ToUInt16($bytes, $optionalHeaderOffset)
    $isPE32Plus = $false
    if ($magic -eq 0x20B) {
        $isPE32Plus = $true  # PE32+
    } elseif ($magic -eq 0x10B) {
        $isPE32Plus = $false # PE32
    } else {
        throw "Unknown PE magic (not PE32/PE32+): $FilePath"
    }

    # CheckSum field is at OptionalHeader + 0x40 for both PE32 and PE32+
    $checkSumOffset = $optionalHeaderOffset + 0x40
    if ($checkSumOffset + 4 -gt $bytes.Length) {
        throw "Invalid checksum offset: $FilePath"
    }

    # DataDirectory base is OptionalHeader + 0x60 (PE32) or +0x70 (PE32+)
    $dataDirBase = if ($isPE32Plus) { $optionalHeaderOffset + 0x70 } else { $optionalHeaderOffset + 0x60 }

    # Certificate Table entry is DataDirectory[4] (IMAGE_DIRECTORY_ENTRY_SECURITY)
    # Each entry is 8 bytes: VirtualAddress, Size
    $certTableEntryOffset = $dataDirBase + (4 * 8)
    if ($certTableEntryOffset + 8 -gt $bytes.Length) {
        throw "Invalid security directory entry offset: $FilePath"
    }

    # For IMAGE_DIRECTORY_ENTRY_SECURITY, VirtualAddress is actually a file offset (not RVA).
    $certFileOffset = [BitConverter]::ToUInt32($bytes, $certTableEntryOffset)
    $certSize       = [BitConverter]::ToUInt32($bytes, $certTableEntryOffset + 4)

    $hasCert = ($certFileOffset -ne 0 -and $certSize -ne 0 -and $certFileOffset -lt $bytes.Length)
    $certStart = if ($hasCert) { [int]$certFileOffset } else { $bytes.Length }
    $certEnd   = if ($hasCert) { [Math]::Min($bytes.Length, [int]($certFileOffset + $certSize)) } else { $bytes.Length }

    $sha = [System.Security.Cryptography.SHA256]::Create()

    function Add-Range([int]$start, [int]$len) {
        if ($len -le 0) { return }
        if ($start -lt 0 -or ($start + $len) -gt $bytes.Length) {
            throw "Range out of bounds: start=$start len=$len for $FilePath"
        }
        $sha.TransformBlock($bytes, $start, $len, $null, 0) | Out-Null
    }

    # Hash layout:
    # 1) [0 .. CheckSum)
    Add-Range 0 ($checkSumOffset)

    # 2) CheckSum treated as zero
    $zero4 = New-Object byte[] 4
    $sha.TransformBlock($zero4, 0, 4, $null, 0) | Out-Null

    # 3) (CheckSum+4 .. SecurityDirEntry)
    Add-Range ($checkSumOffset + 4) ($certTableEntryOffset - ($checkSumOffset + 4))

    # 4) SecurityDirEntry treated as zero (8 bytes)
    $zero8 = New-Object byte[] 8
    $sha.TransformBlock($zero8, 0, 8, $null, 0) | Out-Null

    # 5) (SecurityDirEntry+8 .. certBlobStart)
    $afterSecEntry = $certTableEntryOffset + 8
    Add-Range $afterSecEntry ($certStart - $afterSecEntry)

    # 6) Skip cert blob; hash remainder (cert blob is at end for most PE files, but we handle non-end too)
    if ($hasCert -and $certEnd -lt $bytes.Length) {
        Add-Range $certEnd ($bytes.Length - $certEnd)
    }

    $sha.TransformFinalBlock(@(), 0, 0) | Out-Null
    ([System.BitConverter]::ToString($sha.Hash) -replace '-', '').ToUpperInvariant()
}