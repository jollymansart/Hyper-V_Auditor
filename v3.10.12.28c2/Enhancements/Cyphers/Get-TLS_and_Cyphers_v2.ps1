Write-Host "==== TLS / SSL / Cipher Audit ====" -ForegroundColor Cyan

# -----------------------------
# Helper Functions
# -----------------------------
function Get-RegValue {
    param ($Path, $Name)
    try { (Get-ItemProperty -Path $Path -ErrorAction Stop).$Name }
    catch { $null }
}

function Test-WeakCipher {
    param ($Name)

    $WeakPatterns = @(
        "RC4",
        "DES",
        "3DES",
        "NULL",
        "MD5",
        "EXPORT",
        "_CBC_",
        "_SHA$",
        "RSA_WITH"
    )

    foreach ($pattern in $WeakPatterns) {
        if ($Name -match $pattern) { return $true }
    }
    return $false
}

function Get-CipherStrength {
    param ($cipher)

    if ($cipher -match "GCM|CHACHA20") { return "Modern" }
    elseif ($cipher -match "CBC") { return "Legacy" }
    else { return "Unknown" }
}

# ✅ TLS Version Mapping
function Get-TlsSupport {
    param ($cipher)

    if ($cipher -match "^TLS_AES_" -or $cipher -match "^TLS_CHACHA20_") {
        return "TLS1.3"
    }
    elseif ($cipher -match "_SHA$" -and $cipher -match "CBC") {
        return "TLS1.0;TLS1.1;TLS1.2"
    }
    elseif ($cipher -match "SHA256|SHA384") {
        return "TLS1.2"
    }
    elseif ($cipher -match "NULL") {
        return "TLS1.0;TLS1.1;TLS1.2"
    }
    else {
        return "TLS1.2"
    }
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
# 2. Cipher GPO
# -----------------------------
Write-Host "`n[Cipher Suites (GPO)]" -ForegroundColor Yellow

$cipherPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
$ciphersRaw = Get-RegValue $cipherPolicyPath "Functions"

$cipherList = @()

if ($ciphersRaw) {
    $cipherList = $ciphersRaw -split ","
    Write-Host "GPO Enforced Cipher List Detected ($($cipherList.Count))"
}
else {
    Write-Host "No GPO policy found → Using OS defaults" -ForegroundColor DarkGray
}

# -----------------------------
# 3. Runtime Cipher Detection
# -----------------------------
Write-Host "`n[Runtime Supported Ciphers]" -ForegroundColor Yellow

$runtimeCiphers = @()

# Method 1
try {
    $cipherObjects = Get-TlsCipherSuite

    if ($cipherObjects) {
        if ($cipherObjects[0].PSObject.Properties.Name -contains "Name") {
            $runtimeCiphers = $cipherObjects | Select-Object -ExpandProperty Name
        }
        elseif ($cipherObjects[0].PSObject.Properties.Name -contains "CipherSuite") {
            $runtimeCiphers = $cipherObjects | Select-Object -ExpandProperty CipherSuite
        }
    }
}
catch {
    Write-Host "Get-TlsCipherSuite not supported"
}

# Method 2 (Fallback)
if (-not $runtimeCiphers -or $runtimeCiphers.Count -eq 0) {

    Write-Host "Falling back to registry..." -ForegroundColor DarkGray

    $cipherRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"
    $regValue = Get-ItemProperty -Path $cipherRegPath -Name "Functions" -ErrorAction SilentlyContinue

    if ($regValue) {
        $runtimeCiphers = $regValue.Functions -split ","
    }
}

$runtimeCiphers = $runtimeCiphers | Sort-Object -Unique
Write-Host "Detected $($runtimeCiphers.Count) cipher suites"

# -----------------------------
# 4. Analysis
# -----------------------------
Write-Host "`n[Cipher Analysis]" -ForegroundColor Yellow

$results = @()

foreach ($cipher in $runtimeCiphers) {

    $isWeak    = Test-WeakCipher $cipher
    $strength  = Get-CipherStrength $cipher
    $tlsMap    = Get-TlsSupport $cipher

    if ($cipherList.Count -gt 0) {
        if ($cipherList -contains $cipher) {
            $status = "Allowed (GPO)"
        } else {
            $status = "Denied (Not in GPO)"
        }
    }
    else {
        $status = "Allowed (OS Default)"
    }

    $results += [PSCustomObject]@{
        Cipher    = $cipher
        TLS       = $tlsMap
        Status    = $status
        Weak      = if ($isWeak) { "YES" } else { "NO" }
        Strength  = $strength
        Testable  = if ($status -like "Allowed*") { "YES" } else { "NO" }
    }
}

$results | Sort-Object Cipher | Format-Table -AutoSize

# -----------------------------
# 5. Explicit Overrides
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
# 6. Weak Summary
# -----------------------------
Write-Host "`n[Weak Cipher Summary]" -ForegroundColor Red

$results | Where-Object { $_.Weak -eq "YES" } |
    Sort-Object Cipher |
    Format-Table -AutoSize

# -----------------------------
# 7. 🚨 CRITICAL RISK
# -----------------------------
Write-Host "`n[CRITICAL - REMOVE IMMEDIATELY]" -ForegroundColor Red

$results | Where-Object {
    $_.Cipher -match "NULL" -or $_.Cipher -match "RC4"
} | Format-Table -AutoSize

Write-Host "`n==== Audit Complete ====" -ForegroundColor Cyan