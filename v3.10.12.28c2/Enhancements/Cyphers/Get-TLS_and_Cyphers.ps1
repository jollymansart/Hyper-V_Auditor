Write-Host "==== TLS / SSL / Cipher Audit ====" -ForegroundColor Cyan

# -----------------------------
# Helper
# -----------------------------
function Get-RegValue {
    param ($Path, $Name)
    try { (Get-ItemProperty -Path $Path -ErrorAction Stop).$Name }
    catch { $null }
}

# -----------------------------
# Weak Cipher/Crypto Patterns
# -----------------------------
$WeakPatterns = @(
    "RC4", "DES", "3DES", "NULL", "MD5", "EXPORT"
)

function Test-WeakCipher {
    param ($Name)
    foreach ($pattern in $WeakPatterns) {
        if ($Name -match $pattern) { return $true }
    }
    return $false
}

# -----------------------------
# 1. Protocols
# -----------------------------
Write-Host "`n[Protocols]" -ForegroundColor Yellow

$protocolBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
$protocols = "SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2","TLS 1.3"

foreach ($proto in $protocols) {
    foreach ($role in "Client","Server") {

        $path = "$protocolBase\$proto\$role"

        $enabled  = Get-RegValue $path "Enabled"
        $disabled = Get-RegValue $path "DisabledByDefault"

        if ($enabled -eq 0) { $status = "Disabled" }
        elseif ($enabled -eq 1 -and $disabled -eq 0) { $status = "Enabled" }
        elseif ($disabled -eq 1) { $status = "DisabledByDefault" }
        else { $status = "System Default" }

        Write-Host "$proto [$role] : $status"
    }
}

# -----------------------------
# 2. Cipher Suites (GPO enforced)
# -----------------------------
Write-Host "`n[Cipher Suites (GPO)]" -ForegroundColor Yellow

$cipherPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
$ciphersRaw = Get-RegValue $cipherPolicyPath "Functions"

$cipherList = @()

if ($ciphersRaw) {
    $cipherList = $ciphersRaw -split ","
}
else {
    Write-Host "No GPO policy found → Using OS defaults" -ForegroundColor DarkGray
}

# -----------------------------
# 3. Runtime Cipher List
# -----------------------------
Write-Host "`n[Runtime Supported Ciphers]" -ForegroundColor Yellow

$runtimeCiphers = @()

try {
    $runtimeCiphers = Get-TlsCipherSuite | Select -ExpandProperty Name
}
catch {
    Write-Host "Get-TlsCipherSuite not supported on this OS"
}

# -----------------------------
# 4. Evaluate Ciphers
# -----------------------------
Write-Host "`n[Cipher Analysis]" -ForegroundColor Yellow

$results = @()

$allCiphers = $runtimeCiphers

foreach ($cipher in $allCiphers) {

    $isWeak = Test-WeakCipher $cipher

    if ($cipherList.Count -gt 0) {
        if ($cipherList -contains $cipher) {
            $status = "Allowed (GPO)"
        }
        else {
            $status = "Denied (Not in GPO)"
        }
    }
    else {
        $status = "Allowed (OS Default)"
    }

    $results += [PSCustomObject]@{
        Cipher     = $cipher
        Status     = $status
        Weak       = if ($isWeak) { "YES" } else { "NO" }
        Testable   = if ($status -like "Allowed*") { "YES" } else { "NO" }
    }
}

$results | Sort Cipher | Format-Table -AutoSize

# -----------------------------
# 5. Explicit Cipher Blocks
# -----------------------------
Write-Host "`n[Explicit Cipher Overrides]" -ForegroundColor Yellow

$cipherBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"

if (Test-Path $cipherBase) {
    Get-ChildItem $cipherBase | ForEach-Object {
        $enabled = Get-RegValue $_.PSPath "Enabled"

        $state = switch ($enabled) {
            0 {"Disabled"}
            1 {"Enabled"}
            default {"Default"}
        }

        Write-Host "$($_.PSChildName) : $state"
    }
}

# -----------------------------
# 6. Weak Cipher Summary
# -----------------------------
Write-Host "`n[Weak Cipher Summary]" -ForegroundColor Red

$results | Where-Object {$_.Weak -eq "YES"} | Format-Table -AutoSize

Write-Host "`n==== Audit Complete ====" -ForegroundColor Cyan