$ErrorActionPreference = "Stop"

$iterations = 100000
$securePassword = Read-Host "Shared update password (minimum 16 characters)" -AsSecureString
if ($securePassword.Length -lt 16) {
    $securePassword.Dispose()
    throw "Use a passphrase with at least 16 characters."
}

$pointer = [IntPtr]::Zero
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$kdf = $null
try {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    $salt = New-Object byte[] 16
    $rng.GetBytes($salt)
    $kdf = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
        $password,
        $salt,
        $iterations,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
    $derived = $kdf.GetBytes(32)
    $encoded = "pbkdf2-sha256`$$iterations`$$([Convert]::ToBase64String($salt))`$$([Convert]::ToBase64String($derived))"
    Write-Output $encoded
}
finally {
    if ($kdf) {
        $kdf.Dispose()
    }
    $rng.Dispose()
    if ($pointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
    if ($securePassword) {
        $securePassword.Dispose()
    }
    $password = $null
}
