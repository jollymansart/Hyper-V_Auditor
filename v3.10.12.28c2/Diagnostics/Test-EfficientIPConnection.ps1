<#
.SYNOPSIS
    Test-EfficientIPConnection.ps1
    Validates connectivity to EfficientIP SOLIDserver IPAM before running the Hyper-V Inventory Report.

.DESCRIPTION
    Tests the following:
      1. Credential file exists and can be loaded (DPAPI-encrypted .xml)
      2. DNS resolution for the EfficientIP server
      3. HTTPS connectivity to the SOLIDserver REST API
      4. API authentication with the stored credential
      5. Sample DNS lookup to verify query capability

    Run this BEFORE the report to confirm EfficientIP integration will work.
    If any step fails, the script provides clear remediation guidance.

.PARAMETER Server
    EfficientIP SOLIDserver hostname or IP address.
    Default: reads from Config-OHDC.psd1 if available.

.PARAMETER CredentialPath
    Path to the Export-Clixml credential file for EfficientIP.
    Default: C:\ProgramData\S\efficientip-cred.xml

.PARAMETER IgnoreSSL
    Skip SSL certificate validation (required for self-signed certs).
    Default: $true

.PARAMETER TestHostname
    Optional hostname to perform a test DNS lookup against EfficientIP.
    If omitted, performs a basic API connectivity test only.

.PARAMETER ModulePath
    Path to EfficientIP-Module.psm1. If not specified, searches common locations.

.EXAMPLE
    # Basic connectivity test
    .\Test-EfficientIPConnection.ps1

.EXAMPLE
    # Test with a specific hostname lookup
    .\Test-EfficientIPConnection.ps1 -TestHostname "RICTX-DC-P10"

.EXAMPLE
    # Specify all parameters
    .\Test-EfficientIPConnection.ps1 -Server "RICTX-IPAM-P01.ohdc.com" `
        -CredentialPath "C:\ProgramData\S\efficientip-cred.xml" `
        -TestHostname "RICTX-DC-P10" -IgnoreSSL

.EXAMPLE
    # First-time setup: create the credential file
    Get-Credential -Message "EfficientIP SOLIDserver Admin" | Export-Clixml "C:\ProgramData\S\efficientip-cred.xml"

.NOTES
    Author: Michael George | Overhead Door Corporation
    Version: 3.9.3
    Requires: EfficientIP-Module.psm1 in the Modules folder or specified via -ModulePath
#>
[CmdletBinding()]
param(
    [string]$Server = '',
    [string]$CredentialPath = 'C:\ProgramData\S\efficientip-cred.xml',
    [switch]$IgnoreSSL,
    [string]$TestHostname = '',
    [string]$ModulePath = ''
)

$ErrorActionPreference = 'Continue'
$passed = 0
$failed = 0
$warnings = 0

function Write-TestResult {
    param([string]$Test, [string]$Result, [string]$Detail = '')
    $icon = switch ($Result) {
        'PASS'    { '[PASS]'; $script:passed++ }
        'FAIL'    { '[FAIL]'; $script:failed++ }
        'WARN'    { '[WARN]'; $script:warnings++ }
        'INFO'    { '[INFO]' }
        default   { '[----]' }
    }
    $color = switch ($Result) {
        'PASS' { 'Green' }
        'FAIL' { 'Red' }
        'WARN' { 'Yellow' }
        default { 'Cyan' }
    }
    Write-Host "  $icon " -ForegroundColor $color -NoNewline
    Write-Host $Test -NoNewline
    if ($Detail) { Write-Host " -- $Detail" -ForegroundColor Gray } else { Write-Host "" }
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  EfficientIP SOLIDserver Connectivity Test" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# -----------------------------------------------------------------------
# Step 0: Try to load server/credential from config if not specified
# -----------------------------------------------------------------------
if (-not $Server) {
    $configPaths = @(
        (Join-Path $PSScriptRoot 'Config-OHDC.psd1'),
        (Join-Path $PSScriptRoot 'Config.psd1'),
        (Join-Path (Split-Path $PSScriptRoot) 'Config-OHDC.psd1')
    )
    foreach ($cp in $configPaths) {
        if (Test-Path $cp) {
            try {
                $cfg = Import-PowerShellDataFile $cp
                if ($cfg.EfficientIPServer) {
                    $Server = $cfg.EfficientIPServer
                    if ($cfg.EfficientIPCredPath) { $CredentialPath = $cfg.EfficientIPCredPath }
                    if ($null -ne $cfg.EfficientIPIgnoreSSL) { $IgnoreSSL = $cfg.EfficientIPIgnoreSSL }
                    Write-TestResult "Config loaded from $cp" 'INFO'
                    break
                }
            } catch {}
        }
    }
}

if (-not $Server) {
    Write-TestResult "No EfficientIP server specified" 'FAIL' "Use -Server parameter or set EfficientIPServer in config"
    Write-Host ""
    exit 1
}

Write-TestResult "Target server: $Server" 'INFO'
Write-TestResult "Credential path: $CredentialPath" 'INFO'
Write-Host ""

# -----------------------------------------------------------------------
# Step 1: Credential file
# -----------------------------------------------------------------------
Write-Host "Step 1: Credential File" -ForegroundColor White
$cred = $null
if (Test-Path $CredentialPath) {
    try {
        $cred = Import-Clixml -Path $CredentialPath
        Write-TestResult "Credential file loaded" 'PASS' "$($cred.UserName)"
    }
    catch {
        Write-TestResult "Credential file exists but cannot be decrypted" 'FAIL' "DPAPI decryption requires the same user account that created it. Re-create: Get-Credential | Export-Clixml '$CredentialPath'"
    }
}
else {
    Write-TestResult "Credential file not found: $CredentialPath" 'FAIL' "Create it: Get-Credential -Message 'EfficientIP Admin' | Export-Clixml '$CredentialPath'"
}

if (-not $cred) {
    Write-Host "`nCannot proceed without credentials. Fix Step 1 and re-run." -ForegroundColor Red
    exit 1
}

# -----------------------------------------------------------------------
# Step 2: DNS resolution
# -----------------------------------------------------------------------
Write-Host "`nStep 2: DNS Resolution" -ForegroundColor White
try {
    $dnsResult = [System.Net.Dns]::GetHostEntry($Server)
    $serverIP = ($dnsResult.AddressList | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).IPAddressToString
    Write-TestResult "DNS resolves $Server" 'PASS' "$serverIP"
}
catch {
    Write-TestResult "DNS resolution failed for $Server" 'FAIL' $_.Exception.Message
    Write-Host "`n  Try: nslookup $Server" -ForegroundColor Yellow
    Write-Host "  Or use the IP address directly: -Server '10.x.x.x'" -ForegroundColor Yellow
    exit 1
}

# -----------------------------------------------------------------------
# Step 3: HTTPS connectivity (port 443)
# -----------------------------------------------------------------------
Write-Host "`nStep 3: HTTPS Connectivity" -ForegroundColor White
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect($Server, 443)
    if ($tcp.Connected) {
        Write-TestResult "TCP port 443 open" 'PASS'
        $tcp.Close()
    }
}
catch {
    Write-TestResult "TCP port 443 connection failed" 'FAIL' "Firewall may be blocking HTTPS. Check: Test-NetConnection $Server -Port 443"
    exit 1
}

# -----------------------------------------------------------------------
# Step 4: Load EfficientIP module
# -----------------------------------------------------------------------
Write-Host "`nStep 4: EfficientIP Module" -ForegroundColor White
$moduleLoaded = $false
if ($ModulePath -and (Test-Path $ModulePath)) {
    Import-Module $ModulePath -Force -ErrorAction SilentlyContinue
    $moduleLoaded = $true
}
else {
    # Search common locations
    $searchPaths = @(
        (Join-Path $PSScriptRoot 'Modules\EfficientIP-Module.psm1'),
        (Join-Path $PSScriptRoot 'EfficientIP-Module.psm1'),
        (Join-Path (Split-Path $PSScriptRoot) 'Modules\EfficientIP-Module.psm1')
    )
    foreach ($sp in $searchPaths) {
        if (Test-Path $sp) {
            Import-Module $sp -Force -ErrorAction SilentlyContinue
            $moduleLoaded = $true
            Write-TestResult "Module loaded from $sp" 'INFO'
            break
        }
    }
}

if (Get-Command Connect-EfficientIP -ErrorAction SilentlyContinue) {
    Write-TestResult "Connect-EfficientIP function available" 'PASS'
}
else {
    Write-TestResult "EfficientIP module not loaded" 'FAIL' "Place EfficientIP-Module.psm1 in the Modules folder or use -ModulePath"
    exit 1
}

# -----------------------------------------------------------------------
# Step 5: API Authentication
# -----------------------------------------------------------------------
Write-Host "`nStep 5: API Authentication" -ForegroundColor White
$eipConfig = $null
try {
    $connectParams = @{
        Server     = $Server
        Credential = $cred
    }
    if ($IgnoreSSL) { $connectParams['IgnoreSSL'] = $true }
    $eipConfig = Connect-EfficientIP @connectParams
    Write-TestResult "API authentication successful" 'PASS'
}
catch {
    Write-TestResult "API authentication failed" 'FAIL' $_.Exception.Message
    Write-Host "`n  Common causes:" -ForegroundColor Yellow
    Write-Host "  - Wrong username/password in credential file" -ForegroundColor Yellow
    Write-Host "  - Account locked out or disabled" -ForegroundColor Yellow
    Write-Host "  - API access not enabled for this user in SOLIDserver" -ForegroundColor Yellow
    Write-Host "`n  To re-create credential:" -ForegroundColor Yellow
    Write-Host "  Get-Credential -Message 'EfficientIP' | Export-Clixml '$CredentialPath'" -ForegroundColor Yellow
    exit 1
}

# -----------------------------------------------------------------------
# Step 6: Test DNS lookup (optional)
# -----------------------------------------------------------------------
if ($TestHostname -and $eipConfig) {
    Write-Host "`nStep 6: Test DNS Lookup" -ForegroundColor White
    try {
        $lookupResult = Get-EfficientIPByHostname -Config $eipConfig -Hostname $TestHostname -ExactMatch -ErrorAction Stop
        if ($lookupResult) {
            $resultArray = @($lookupResult)
            Write-TestResult "Hostname lookup: $TestHostname" 'PASS' "$($resultArray.Count) record(s) found"
            foreach ($r in $resultArray) {
                $ip = if ($r.IPAddress) { $r.IPAddress }
                      elseif ($r.hostaddr) { try { [System.Net.IPAddress]::Parse($r.hostaddr).IPAddressToString } catch { $r.hostaddr } }
                      else { '(no IP field)' }
                $mac = if ($r.mac_addr) { $r.mac_addr } else { '' }
                $name = if ($r.name) { $r.name } else { $TestHostname }
                Write-TestResult "  Record: $name -> $ip" 'INFO' $(if ($mac) { "MAC: $mac" } else { '' })
            }
        }
        else {
            Write-TestResult "Hostname lookup: $TestHostname" 'WARN' "No records found (hostname may not exist in IPAM)"
        }
    }
    catch {
        Write-TestResult "Hostname lookup failed: $TestHostname" 'FAIL' $_.Exception.Message
    }
}
elseif ($eipConfig) {
    Write-Host "`nStep 6: Test DNS Lookup (skipped -- use -TestHostname to test)" -ForegroundColor Gray
}

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  Results: $passed PASS, $failed FAIL, $warnings WARN" -ForegroundColor $(if ($failed -gt 0) { 'Red' } elseif ($warnings -gt 0) { 'Yellow' } else { 'Green' })
if ($failed -eq 0) {
    Write-Host "  EfficientIP integration is ready for the Hyper-V Inventory Report." -ForegroundColor Green
}
else {
    Write-Host "  Fix the failures above before running the report." -ForegroundColor Red
}
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""
