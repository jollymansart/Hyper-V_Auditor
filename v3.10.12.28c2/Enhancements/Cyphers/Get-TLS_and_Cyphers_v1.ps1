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
        "_CBC_",     # CBC mode (legacy)
        "_SHA$",     # SHA1
        "RSA_WITH"   # No forward secrecy
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

# -----------------------------
# 1. Protocol Audit
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
# 2. Cipher Suite Policy (GPO)
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
# 3. Runtime Cipher Detection (Method 1 + Method 2 fallback)
# -----------------------------
Write-Host "`n[Runtime Supported Ciphers]" -ForegroundColor Yellow

$runtimeCiphers = @()

# Method 1: Get-TlsCipherSuite
try {
    $cipherObjects = Get-TlsCipherSuite

    if ($cipherObjects) {
        if ($cipherObjects[0].PSObject.Properties.Name -contains "Name") {
            $runtimeCiphers = $cipherObjects | Select-Object -ExpandProperty Name
        }
        elseif ($cipherObjects[0].PSObject.Properties.Name -contains "CipherSuite") {
            $runtimeCiphers = $cipherObjects | Select-Object -ExpandProperty CipherSuite
        }
        else {
            Write-Host "Unknown cipher property format"
        }
    }
}
catch {
    Write-Host "Get-TlsCipherSuite not supported on this OS"
}

# Method 2: Registry fallback
if (-not $runtimeCiphers -or $runtimeCiphers.Count -eq 0) {

    Write-Host "Falling back to registry-based enumeration..." -ForegroundColor DarkGray

    $cipherRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"
    $regValue = Get-ItemProperty -Path $cipherRegPath -Name "Functions" -ErrorAction SilentlyContinue

    if ($regValue) {
        $runtimeCiphers = $regValue.Functions -split ","
    }
}

# Deduplicate
$runtimeCiphers = $runtimeCiphers | Sort-Object -Unique

Write-Host "Detected $($runtimeCiphers.Count) cipher suites"

# -----------------------------
# 4. Cipher Analysis
# -----------------------------
Write-Host "`n[Cipher Analysis]" -ForegroundColor Yellow

$results = @()

foreach ($cipher in $runtimeCiphers) {

    $isWeak = Test-WeakCipher $cipher
    $strength = Get-CipherStrength $cipher

    # Allowed / Denied logic
    if ($cipherList.Count -gt 0) {
        if ($cipherList -contains $cipher) {
            $status = "Allowed (GPO)"
        }
        else {
            $status = "Denied (Not in GPO)"
        }
    }
    else {
        $status = "Allowed (OS Default - Not Restricted)"
    }

    $results += [PSCustomObject]@{
        Cipher    = $cipher
        Status    = $status
        Weak      = if ($isWeak) { "YES" } else { "NO" }
        Strength  = $strength
        Testable  = if ($status -like "Allowed*") { "YES" } else { "NO" }
    }
}

$results | Sort-Object Cipher | Format-Table -AutoSize

# -----------------------------
# 5. Explicit Cipher Overrides
# -----------------------------
Write-Host "`n[Explicit Cipher Overrides]" -ForegroundColor Yellow

$cipherBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"

if (Test-Path $cipherBase) {
    Get-ChildItem $cipherBase | ForEach-Object {
        $enabled = Get-RegValue $_.PSPath "Enabled"

        $state = switch ($enabled) {
            0 {"Disabled"}
            1 {"Enabled"}
            default {"System Default"}
        }

        Write-Host "$($_.PSChildName) : $state"
    }
}
else {
    Write-Host "No explicit overrides configured"
}

# -----------------------------
# 6. Weak Cipher Summary
# -----------------------------
Write-Host "`n[Weak Cipher Summary]" -ForegroundColor Red

$results | Where-Object { $_.Weak -eq "YES" } |
    Sort-Object Cipher |
    Format-Table -AutoSize

Write-Host "`n==== Audit Complete ====" -ForegroundColor Cyan