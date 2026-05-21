# Requires: PowerShell 5.1+
# Works on: Windows Server 2008R2 -> 2022+

[OutputType([PSCustomObject])]

Write-Host "==== TLS/SSL & Cipher Audit ====" -ForegroundColor Cyan

# -----------------------------
# Helper function
# -----------------------------
function Get-RegistryValueSafe {
    param ($Path, $Name)

    try {
        (Get-ItemProperty -Path $Path -ErrorAction Stop).$Name
    }
    catch {
        $null
    }
}

# -----------------------------
# 1. Protocols (Schannel)
# -----------------------------
Write-Host "`n[Protocols]" -ForegroundColor Yellow

$protocolBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

$protocols = @(
    "SSL 2.0","SSL 3.0",
    "TLS 1.0","TLS 1.1","TLS 1.2","TLS 1.3"
)

$protocolResults = foreach ($proto in $protocols) {
    foreach ($role in @("Client","Server")) {
        $path = "$protocolBase\$proto\$role"

        $enabled    = Get-RegistryValueSafe $path "Enabled"
        $disabled   = Get-RegistryValueSafe $path "DisabledByDefault"

        if ($enabled -eq $null -and $disabled -eq $null) {
            $status = "System Default"
        }
        elseif ($enabled -eq 1 -and $disabled -eq 0) {
            $status = "Enabled"
        }
        elseif ($enabled -eq 0) {
            $status = "Disabled"
        }
        elseif ($disabled -eq 1) {
            $status = "DisabledByDefault"
        }
        else {
            $status = "Unknown"
        }

        [PSCustomObject]@{
            Protocol = $proto
            Role     = $role
            Status   = $status
            Path     = $path
        }
    }
}

$protocolResults | Format-Table -AutoSize

# -----------------------------
# 2. Cipher Suites (Group Policy Order)
# -----------------------------
Write-Host "`n[Cipher Suites - Policy Order]" -ForegroundColor Yellow

$cipherOrderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
$cipherOrder = Get-RegistryValueSafe $cipherOrderPath "Functions"

if ($cipherOrder) {
    $cipherList = $cipherOrder -split ","

    $cipherObjects = $cipherList | ForEach-Object {
        [PSCustomObject]@{
            CipherSuite = $_.Trim()
            Source      = "GroupPolicy"
        }
    }

    $cipherObjects | Select-Object -First 20 | Format-Table
    Write-Host "... total: $($cipherList.Count) suites"
}
else {
    Write-Host "No GPO-defined cipher order found (using OS defaults)" -ForegroundColor DarkGray
}

# -----------------------------
# 3. Schannel Ciphers (explicit allow/deny)
# -----------------------------
Write-Host "`n[Schannel Cipher Controls]" -ForegroundColor Yellow

$cipherBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"

if (Test-Path $cipherBase) {
    $cipherKeys = Get-ChildItem $cipherBase

    $cipherStatus = foreach ($key in $cipherKeys) {
        $enabled = Get-RegistryValueSafe $key.PSPath "Enabled"

        [PSCustomObject]@{
            Cipher   = $key.PSChildName
            Enabled  = if ($enabled -eq 0) {"Disabled"}
                        elseif ($enabled -eq 1) {"Enabled"}
                        else {"System Default"}
        }
    }

    $cipherStatus | Format-Table -AutoSize
}
else {
    Write-Host "No explicit cipher restrictions found (using defaults)"
}

# -----------------------------
# 4. .NET TLS Settings
# -----------------------------
Write-Host "`n[.NET TLS Settings]" -ForegroundColor Yellow

$netPath = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
$netPathWow = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"

$netSettings = @(
    @{ Path=$netPath; Name="64-bit" },
    @{ Path=$netPathWow; Name="32-bit" }
)

foreach ($entry in $netSettings) {
    $strongCrypto = Get-RegistryValueSafe $entry.Path "SchUseStrongCrypto"
    $systemDefault = Get-RegistryValueSafe $entry.Path "SystemDefaultTlsVersions"

    [PSCustomObject]@{
        Architecture        = $entry.Name
        SchUseStrongCrypto  = if ($strongCrypto -eq 1) {"Enabled"} else {"Disabled/Default"}
        SystemDefaultTLS    = if ($systemDefault -eq 1) {"Enabled"} else {"Disabled/Default"}
    }
} | Format-Table

# -----------------------------
# 5. OS-supported cipher suites (runtime view)
# -----------------------------
Write-Host "`n[Supported Cipher Suites (Runtime)]" -ForegroundColor Yellow

try {
    $ciphers = Get-TlsCipherSuite
    $ciphers | Select-Object -First 15 Name | Format-Table
    Write-Host "... total: $($ciphers.Count)"
}
catch {
    Write-Host "Get-TlsCipherSuite not available on this OS (older systems)" -ForegroundColor DarkGray
}

Write-Host "`n==== Audit Complete ====" -ForegroundColor Cyan