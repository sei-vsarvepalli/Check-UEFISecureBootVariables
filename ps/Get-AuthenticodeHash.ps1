function Get-AuthenticodeSha256Hex {
    param(
        [Parameter(Mandatory = $true)]
        [string]$peFile
    )

    $peHeader = [System.IO.File]::ReadAllBytes($peFile)
    $optionalHeaderOffset = [BitConverter]::ToUInt32($peHeader, 60) + 24  # Offset of Optional Header
    # Zero the checksum
    [BitConverter]::GetBytes(0) | ForEach-Object { $peHeader[$optionalHeaderOffset + 88 + $_] = 0 }
    # Zero IMAGE_DIRECTORY_ENTRY_SECURITY
a[$optionalHeaderOffset + 96] = 0
    a[$optionalHeaderOffset + 97] = 0
    a[$optionalHeaderOffset + 98] = 0
    a[$optionalHeaderOffset + 99] = 0
    a[$optionalHeaderOffset + 100] = 0
    a[$optionalHeaderOffset + 101] = 0
    a[$optionalHeaderOffset + 102] = 0
    a[$optionalHeaderOffset + 103] = 0

    $hash = [System.Security.Cryptography.SHA256]::Create()
    $hashResult = $hash.ComputeHash($peHeader)
    return [BitConverter]::ToString($hashResult).Replace('-','').ToLower()
}