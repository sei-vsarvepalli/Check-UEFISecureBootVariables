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

    # DOS header e_lfanew
    $peOffset = [BitConverter]::ToUInt32($bytes, 0x3C)

    # PE signature "PE\0\0"
    if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset+1] -ne 0x45 -or $bytes[$peOffset+2] -ne 0x00 -or $bytes[$peOffset+3] -ne 0x00) {
        throw "Missing PE signature: $FilePath"
    }

    $optionalHeaderOffset = $peOffset + 4 + 20
    $magic = [BitConverter]::ToUInt16($bytes, $optionalHeaderOffset)

    $isPE32Plus = $false
    if ($magic -eq 0x20B) { $isPE32Plus = $true }
    elseif ($magic -eq 0x10B) { $isPE32Plus = $false }
    else { throw "Unknown PE magic (not PE32/PE32+): $FilePath" }

    # CheckSum field offset (same for PE32/PE32+)
    $checkSumOffset = $optionalHeaderOffset + 0x40

    # DataDirectory base offset
    $dataDirBase = if ($isPE32Plus) { $optionalHeaderOffset + 0x70 } else { $optionalHeaderOffset + 0x60 }

    # IMAGE_DIRECTORY_ENTRY_SECURITY (index 4)
    $certTableEntryOffset = $dataDirBase + (4 * 8)

    $certFileOffset = [BitConverter]::ToUInt32($bytes, $certTableEntryOffset)
    $certSize       = [BitConverter]::ToUInt32($bytes, $certTableEntryOffset + 4)

    $hasCert = ($certFileOffset -ne 0 -and $certSize -ne 0 -and $certFileOffset -lt $bytes.Length)
    $certStart = if ($hasCert) { [int]$certFileOffset } else { $bytes.Length }
    $certEnd   = if ($hasCert) { [Math]::Min($bytes.Length, [int]($certFileOffset + $certSize)) } else { $bytes.Length }

    $sha = [System.Security.Cryptography.SHA256]::Create()

    function Add-Range([int]$start, [int]$len) {
        if ($len -le 0) { return }
        $sha.TransformBlock($bytes, $start, $len, $null, 0) | Out-Null
    }

    # Hash everything, but:
    # - CheckSum is zeroed
    # - Security directory entry is zeroed
    # - Certificate blob is excluded
    Add-Range 0 ($checkSumOffset)

    $zero4 = New-Object byte[] 4
    $sha.TransformBlock($zero4, 0, 4, $null, 0) | Out-Null

    Add-Range ($checkSumOffset + 4) ($certTableEntryOffset - ($checkSumOffset + 4))

    $zero8 = New-Object byte[] 8
    $sha.TransformBlock($zero8, 0, 8, $null, 0) | Out-Null

    $afterSec = $certTableEntryOffset + 8
    Add-Range $afterSec ($certStart - $afterSec)

    if ($hasCert -and $certEnd -lt $bytes.Length) {
        Add-Range $certEnd ($bytes.Length - $certEnd)
    }

    $sha.TransformFinalBlock(@(), 0, 0) | Out-Null
    ([System.BitConverter]::ToString($sha.Hash) -replace '-', '').ToUpperInvariant()
}