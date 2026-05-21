Function Test-SingleServer
{
<#
.SYNOPSIS
    Quick test -- verify a credential can connect to a specific VM or server.
    Use this to confirm overheaddoor.com or creative.com VMs are reachable
    before running the full 42-minute inventory.

.DESCRIPTION
    Takes a saved credential file (or prompts) and tests it against one target:
      - WinRM Test-WSMan (port 5985/5986)
      - Invoke-Command (actually runs a command remotely)
      - Get-ADComputer lookup (confirms AD auth works for that machine's domain)
      - Optional CredSSP test (what the inventory uses for OS collection)

.EXAMPLES
    # Test overheaddoor.com credential against a specific VM:
    .\Test-SingleServer.ps1 -Target MHOH-SOMEVM-P01 -CredFile "C:\ProgramData\S\HyperV-Cred-overheaddoor.xml"

    # Prompt for credential instead of loading from file:
    .\Test-SingleServer.ps1 -Target MHOH-SOMEVM-P01.overheaddoor.com -PromptForCred

    # Test with CredSSP (what the inventory actually uses for deep OS collection):
    .\Test-SingleServer.ps1 -Target MHOH-SOMEVM-P01 -CredFile "C:\ProgramData\S\HyperV-Cred-overheaddoor.xml" -TestCredSSP

    # Test your primary ohdc.com credential (current Windows session):
    .\Test-SingleServer.ps1 -Target RICTX-UCSHV-P1.ohdc.com -UseCurrentUser
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Target,                  # VM or server name/FQDN to test against

    [string]$CredFile  = '',          # Path to .xml credential file (Import-Clixml format)
    [switch]$PromptForCred,           # Prompt for credential interactively
    [switch]$UseCurrentUser,          # Use current Windows session (no credential)
    [switch]$TestCredSSP,             # Also test CredSSP (requires CredSSP to be enabled)
    [string]$Domain    = ''           # Domain FQDN for AD lookup (auto-detected if blank)
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'

function Pass  { Write-Host "    [PASS] $args" -ForegroundColor Green  }
function Fail  { Write-Host "    [FAIL] $args" -ForegroundColor Red    }
function Warn  { Write-Host "    [WARN] $args" -ForegroundColor Yellow }
function Info  { Write-Host "    [INFO] $args" -ForegroundColor Gray   }

# ---- Load credential ----
$cred = $null
if ($UseCurrentUser) {
    Info "Using current Windows session (no explicit credential)"
} elseif ($PromptForCred) {
    $cred = Get-Credential -Message "Enter credentials for $Target"
} elseif ($CredFile) {
    if (-not (Test-Path $CredFile)) { Write-Host "Credential file not found: $CredFile" -ForegroundColor Red; return }
    try   { $cred = Import-Clixml $CredFile }
    catch { Write-Host "Failed to load credential: $($_.Exception.Message)" -ForegroundColor Red; return }
} else {
    Write-Host "Specify -CredFile, -PromptForCred, or -UseCurrentUser" -ForegroundColor Yellow
    return
}

$userName = if ($cred) { $cred.UserName } else { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }

Write-Host ""
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host "  SINGLE SERVER CREDENTIAL TEST" -ForegroundColor Cyan
Write-Host "  Target : $Target" -ForegroundColor White
Write-Host "  User   : $userName" -ForegroundColor White
Write-Host "  Time   : $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor White
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""

# ---- Test 1: Ping ----
Write-Host "  [1/5] Ping test..." -ForegroundColor White
$pingOK = Test-Connection -ComputerName $Target -Count 2 -Quiet -ErrorAction SilentlyContinue
if ($pingOK) { Pass "Ping OK" } else { Warn "No ping response (WinRM may still work if ICMP is blocked)" }

# ---- Test 2: WinRM port ----
Write-Host "  [2/5] WinRM port check (5985)..." -ForegroundColor White
$portOK = $false
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $async = $tcp.BeginConnect($Target, 5985, $null, $null)
    $wait  = $async.AsyncWaitHandle.WaitOne(3000, $false)
    if ($wait -and $tcp.Connected) { $portOK = $true }
    $tcp.Close()
} catch {}
if ($portOK) { Pass "Port 5985 open" } else { Fail "Port 5985 not responding -- WinRM may be disabled or firewall blocking" }

# ---- Test 3: Test-WSMan ----
Write-Host "  [3/5] Test-WSMan (WinRM authentication)..." -ForegroundColor White
try {
    $wsP = @{ ComputerName = $Target; ErrorAction = 'Stop' }
    if ($cred) {
        $wsP['Credential']     = $cred
        $wsP['Authentication'] = 'Negotiate'   # Kerberos preferred, NTLM fallback
    }
    $wsResult = Test-WSMan @wsP
    Pass "Test-WSMan OK -- ProductVersion: $($wsResult.ProductVersion)"
} catch {
    $msg = ($_.Exception.Message -split '\r?\n')[0]
    Fail "Test-WSMan failed: $msg"
    Info "This credential cannot authenticate to $Target via WinRM"
}

# ---- Test 4: Invoke-Command ----
Write-Host "  [4/5] Invoke-Command (remote execution)..." -ForegroundColor White
$invokeSuccess = $false
foreach ($authMethod in @('Kerberos', 'Negotiate')) {
    try {
        $icP = @{
            ComputerName = $Target
            ErrorAction  = 'Stop'
            ScriptBlock  = {
                [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    Domain       = $env:USERDOMAIN
                    OS           = (Get-WmiObject Win32_OperatingSystem -EA SilentlyContinue).Caption
                    PSVersion    = $PSVersionTable.PSVersion.ToString()
                    WinRMAuth    = $PSSenderInfo.ConnectionString
                }
            }
        }
        if ($cred) {
            $icP['Credential']     = $cred
            $icP['Authentication'] = $authMethod
        }
        $result = Invoke-Command @icP
        Pass "Invoke-Command OK via $authMethod"
        Pass "  Remote computer : $($result.ComputerName)"
        Pass "  Domain          : $($result.Domain)"
        Pass "  OS              : $($result.OS)"
        Pass "  PS Version      : $($result.PSVersion)"
        $invokeSuccess = $true
        break
    } catch {
        $msg = ($_.Exception.Message -split '\r?\n')[0]
        if ($authMethod -eq 'Kerberos') {
            Info "Kerberos failed ($msg), trying Negotiate..."
        } else {
            Fail "Invoke-Command failed ($authMethod): $msg"
        }
    }
}

# ---- Test 5: CredSSP (optional) ----
if ($TestCredSSP) {
    Write-Host "  [5/5] CredSSP test..." -ForegroundColor White
    if (-not $cred) {
        Warn "CredSSP test skipped -- requires explicit credential (not current user)"
    } else {
        try {
            $csP = @{
                ComputerName = $Target
                Credential   = $cred
                Authentication = 'Credssp'
                ErrorAction  = 'Stop'
                ScriptBlock  = { "CredSSP OK on $env:COMPUTERNAME" }
            }
            $csResult = Invoke-Command @csP
            Pass "CredSSP OK: $csResult"
        } catch {
            $msg = ($_.Exception.Message -split '\r?\n')[0]
            Warn "CredSSP failed: $msg"
            Info "If CredSSP is not configured on $Target, this is expected."
            Info "Enable with: Enable-WSManCredSSP -Role Server on the target."
        }
    }
} else {
    Info "[5/5] CredSSP test skipped (use -TestCredSSP to enable)"
}

# ---- AD lookup ----
if (Get-Command Get-ADComputer -ErrorAction SilentlyContinue) {
    Write-Host ""
    Write-Host "  [AD]  AD computer object lookup..." -ForegroundColor White
    $shortName = ($Target -split '\.')[0].ToUpper()
    # Determine domain from target FQDN or parameter
    $adDomain = $Domain
    if (-not $adDomain -and $Target -match '\.(.+\..+)$') { $adDomain = $Matches[1] }
    
    try {
        $adP = @{ Identity = $shortName; Properties = @('ServicePrincipalNames','TrustedForDelegation','msDS-AllowedToDelegateTo','ms-Mcs-AdmPwd','msLAPS-Password'); ErrorAction = 'Stop' }
        if ($adDomain) { $adP['Server'] = $adDomain }
        if ($cred -and $adDomain) { $adP['Credential'] = $cred }
        $adObj = Get-ADComputer @adP
        Pass "AD object found: $($adObj.DistinguishedName)"
        
        $delType = if ($adObj.TrustedForDelegation) { "UNCONSTRAINED (CRITICAL)" }
                   elseif ($adObj.'msDS-AllowedToDelegateTo') { "KCD" }
                   else { "None" }
        Info "  Delegation  : $delType"
        
        $spnCount = @($adObj.ServicePrincipalNames).Count
        $wsmanOK  = @($adObj.ServicePrincipalNames | Where-Object { $_ -match '^WSMAN/' }).Count
        Info "  SPNs        : $spnCount total, $wsmanOK WSMAN"
        if ($wsmanOK -eq 0) { Warn "  No WSMAN SPNs -- Kerberos auth will use NTLM fallback" }
        
        $laps = if ($adObj.'msLAPS-Password') { "Windows LAPS" } elseif ($adObj.'ms-Mcs-AdmPwd') { "Legacy LAPS" } else { "None" }
        Info "  LAPS        : $laps"
    } catch {
        Fail "AD lookup failed: $(($_.Exception.Message -split '\r?\n')[0])"
        if ($adDomain) { Info "  Tried server: $adDomain" }
    }
}

Write-Host ""
Write-Host "=======================================" -ForegroundColor Cyan
if ($invokeSuccess) {
    Write-Host "  RESULT: Credential is working for $Target" -ForegroundColor Green
} else {
    Write-Host "  RESULT: Credential issues detected for $Target" -ForegroundColor Yellow
    Write-Host "  This VM will not have OS data in the inventory report." -ForegroundColor Yellow
}
Write-Host ""

}
