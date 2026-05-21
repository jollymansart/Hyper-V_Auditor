function Test-Credientials
{

<#
.SYNOPSIS
    Credential Validation Test Script -- Overhead Door Corporation
    Tests each domain credential for AD and WinRM connectivity before running the inventory.

.DESCRIPTION
    Tests three things per credential:
      1. AD Authentication  -- Can we reach a DC and authenticate? (Get-ADDomain)
      2. WinRM Kerberos     -- Can we open a WinRM session to the domain? (Test-WSMan)
      3. WinRM Invoke       -- Can we actually run a remote command? (Invoke-Command)

    The WinRM test in Run_Report.ps1 was using no authentication flag which caused a false
    error for non-primary domain credentials. This script uses the correct Kerberos/Negotiate
    approach and shows exactly what the inventory run will see.

.NOTES
    Run this BEFORE starting the 42-minute inventory to confirm all credentials work.
    If overheaddoor.com WinRM shows WARN, the VMs in that domain will have no OS data.

.EXAMPLE
    # Test all credentials from your config file:
    .\Test-Credentials.ps1

    # Test a specific domain only:
    .\Test-Credentials.ps1 -Domain overheaddoor.com

    # Test against a specific DC (useful to confirm which DC is being hit):
    .\Test-Credentials.ps1 -Domain overheaddoor.com -DCName overheaddoor-dc01.overheaddoor.com

    # Test with a credential you type in right now (no saved .xml needed):
    .\Test-Credentials.ps1 -Domain overheaddoor.com -PromptForCred

    # Run all tests silently and show only failures:
    .\Test-Credentials.ps1 -FailuresOnly
#>
[CmdletBinding()]
param(
    [string]$ConfigPath   = "",
    [string]$Domain       = '',           # Filter to one domain only (leave blank = test all)
    [string]$DCName       = '',           # Override DC name for WinRM test
    [switch]$PromptForCred,               # Prompt for credential instead of loading from file
    [switch]$FailuresOnly,                # Only show WARN/FAIL results
    [switch]$SkipWinRM                    # Skip WinRM tests (AD-only mode)
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'

# Resolve ConfigPath default -- $PSScriptRoot is empty when run via UNC path from a
# different working directory (e.g. running from C:\Windows\system32 via full UNC path).
if (-not $ConfigPath -or $ConfigPath -eq '') {
    $scriptDir = if ($PSScriptRoot -and $PSScriptRoot -ne '') {
        $PSScriptRoot
    } else {
        Split-Path -Parent $MyInvocation.MyCommand.Path
    }
    $ConfigPath = Join-Path $scriptDir 'Config-OHDC.psd1'
}

# ============================================================
# Helpers
# ============================================================
function Write-Result {
    param([string]$Status, [string]$Message, [string]$Detail = '')
    $color = switch ($Status) {
        'OK'   { 'Green'  }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red'    }
        'INFO' { 'Cyan'   }
        default{ 'Gray'   }
    }
    Write-Host "  [$Status] $Message" -ForegroundColor $color
    if ($Detail) { Write-Host "         $Detail" -ForegroundColor DarkYellow }
}

function Test-ADAuth {
    param([string]$DomainFQDN, [PSCredential]$Cred, [bool]$IsPrimary)
    # Primary: ADWS via Get-ADDomain (requires port 9389 -- introduced in Server 2008)
    # Server 2003 DCs do not have ADWS. Fallback to direct LDAP bind via DirectoryServices.
    try {
        $p = @{ Server = $DomainFQDN; ErrorAction = 'Stop' }
        if (-not $IsPrimary -and $Cred) { $p['Credential'] = $Cred }
        $d = Get-ADDomain @p
        return @{ OK = $true; Method = 'ADWS'; Detail = "DC: $($d.PDCEmulator)  NetBIOS: $($d.NetBIOSName)  DFL: $($d.DomainMode)" }
    }
    catch {
        $adwsError = ($_.Exception.Message -split '
?
')[0]
        $isAdwsIssue = $adwsError -match 'Unable to contact|9389|not.*running|does not exist|cannot be contacted'
        if (-not $isAdwsIssue) {
            return @{ OK = $false; Method = 'ADWS'; Detail = $adwsError }
        }
        # LDAP fallback -- works against Server 2003 and any DC
        try {
            if ($Cred -and -not $IsPrimary) {
                $de = New-Object System.DirectoryServices.DirectoryEntry(
                    "LDAP://$DomainFQDN",
                    $Cred.UserName,
                    $Cred.GetNetworkCredential().Password
                )
            } else {
                $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainFQDN")
            }
            $bindName = $de.Name   # Forces authentication -- throws on failure
            if ($null -eq $bindName -and $de.SchemaClassName -eq $null) { throw "Empty bind" }
            $de.Dispose()
            return @{ OK = $true; Method = 'LDAP'; Detail = "LDAP bind OK (ADWS unavailable -- likely Server 2003 DC). AD audit data skipped for this domain; OS inventory still runs." }
        }
        catch {
            $ldapErr = ($_.Exception.Message -split '
?
')[0]
            return @{ OK = $false; Method = 'LDAP'; Detail = "ADWS: $adwsError | LDAP: $ldapErr" }
        }
    }
}

function Test-WinRMAuth {
    param([string]$Target, [PSCredential]$Cred, [bool]$IsPrimary)
    # Use Negotiate (Kerberos/NTLM) with explicit credential for cross-domain tests.
    # Do NOT use 'Default' authentication when supplying a credential -- that causes
    # the "no authentication flag" error seen in the Run_Report.ps1 output.
    try {
        $p = @{ ComputerName = $Target; ErrorAction = 'Stop' }
        if (-not $IsPrimary -and $Cred) {
            $p['Credential']      = $Cred
            $p['Authentication']  = 'Negotiate'
        }
        $null = Test-WSMan @p
        return @{ OK = $true; Detail = "WinRM endpoint responding on $Target" }
    } catch {
        return @{ OK = $false; Detail = ($_.Exception.Message -split '\r?\n')[0] }
    }
}

function Test-WinRMInvoke {
    param([string]$Target, [PSCredential]$Cred, [bool]$IsPrimary)
    try {
        $p = @{ ComputerName = $Target; ErrorAction = 'Stop'; ScriptBlock = { $env:COMPUTERNAME } }
        if (-not $IsPrimary -and $Cred) {
            $p['Credential']      = $Cred
            $p['Authentication']  = 'Kerberos'   # prefer Kerberos for domain accounts
        }
        $result = Invoke-Command @p
        return @{ OK = $true; Detail = "Remote execution OK -- server returned: $result" }
    } catch {
        # Fall back to Negotiate if Kerberos fails
        try {
            $p['Authentication'] = 'Negotiate'
            $result = Invoke-Command @p
            return @{ OK = $true; Detail = "Remote exec OK via Negotiate (not Kerberos) -- server: $result" }
        } catch {
            return @{ OK = $false; Detail = ($_.Exception.Message -split '\r?\n')[0] }
        }
    }
}

# ============================================================
# Load config and credentials
# ============================================================
Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  CREDENTIAL VALIDATION TEST" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

if ($PromptForCred) {
    if (-not $Domain) { $Domain = Read-Host "Enter domain FQDN to test (e.g. overheaddoor.com)" }
    $manualCred = Get-Credential -Message "Enter credentials for $Domain"
    $testList   = @(@{
        Name        = 'Manual-Test'
        DomainFQDN  = $Domain
        Cred        = $manualCred
        IsPrimary   = $false
        StoredPath  = '(manual entry)'
    })
} else {
    if (-not (Test-Path $ConfigPath)) {
        Write-Host "Config not found: $ConfigPath" -ForegroundColor Red
        Write-Host "Run from the report directory, or specify -ConfigPath" -ForegroundColor Red
        return
    }
    $config   = Import-PowerShellDataFile $ConfigPath
    $testList = @()
    foreach ($c in $config.Credentials) {
        if (-not $c.DomainFQDN -or $c.DomainFQDN -eq '') { continue }
        if ($Domain -and $c.DomainFQDN -notlike "*$Domain*") { continue }
        $cred = $null
        if (Test-Path $c.StoredPath) {
            try   { $cred = Import-Clixml $c.StoredPath }
            catch { Write-Result 'FAIL' "$($c.Name): Cannot load credential from $($c.StoredPath)" $_.Exception.Message; continue }
        } else {
            Write-Result 'FAIL' "$($c.Name): Credential file not found: $($c.StoredPath)"
            continue
        }
        $testList += @{
            Name       = $c.Name
            DomainFQDN = $c.DomainFQDN
            Cred       = $cred
            IsPrimary  = [bool]$c.IsPrimary
            StoredPath = $c.StoredPath
        }
    }
}

if ($testList.Count -eq 0) {
    Write-Host "No credentials to test." -ForegroundColor Yellow; return
}

# ============================================================
# Run tests
# ============================================================
$overallPass = $true

foreach ($t in $testList) {
    $domFQDN  = $t.DomainFQDN
    $cred     = $t.Cred
    $isPri    = $t.IsPrimary
    $userName = if ($cred) { $cred.UserName } else { '(current user)' }
    $dcTarget = if ($DCName) { $DCName } else { $domFQDN }

    Write-Host ""
    Write-Host "  Domain   : $domFQDN" -ForegroundColor White
    Write-Host "  User     : $userName" -ForegroundColor White
    Write-Host "  Primary  : $isPri" -ForegroundColor White
    Write-Host "  CredFile : $($t.StoredPath)" -ForegroundColor DarkGray
    Write-Host "  DCTarget : $dcTarget" -ForegroundColor DarkGray
    Write-Host ""

    # Test 1: AD Auth
    Write-Host "    Test 1/3: AD Authentication..." -ForegroundColor Gray -NoNewline
    $adResult = Test-ADAuth -DomainFQDN $domFQDN -Cred $cred -IsPrimary $isPri
    Write-Host ""
    if ($adResult.OK) {
        $adLabel = if ($adResult.Method -eq 'LDAP') { "AD Auth OK [LDAP fallback]" } else { "AD Auth OK" }
        if (-not $FailuresOnly) { Write-Result 'OK' "$adLabel -- $domFQDN" $adResult.Detail }
        if ($adResult.Method -eq 'LDAP') {
            Write-Host "         Server 2003 DC detected (no ADWS). Delegation/SPN/LAPS audit will be skipped" -ForegroundColor DarkYellow
            Write-Host "         for $domFQDN -- OS inventory (WinRM) will still run per-VM." -ForegroundColor DarkYellow
        }
    } else {
        Write-Result 'FAIL' "AD Auth FAILED -- $domFQDN" $adResult.Detail
        $overallPass = $false
    }

    if ($SkipWinRM) { continue }

    # Test 2: WinRM connectivity
    Write-Host "    Test 2/3: WinRM (Test-WSMan)..." -ForegroundColor Gray -NoNewline
    $wsmanResult = Test-WinRMAuth -Target $dcTarget -Cred $cred -IsPrimary $isPri
    Write-Host ""
    if ($wsmanResult.OK) {
        if (-not $FailuresOnly) { Write-Result 'OK' "WinRM OK -- $dcTarget" $wsmanResult.Detail }
    } else {
        # 0x8009030e = cross-domain Kerberos restriction when targeting a DC from a foreign domain.
        # This is a FALSE ALARM -- the inventory connects to each VM directly, not through the DC.
        $isCrossDomainBlock = $wsmanResult.Detail -match '0x8009030e|8009030e|logon session does not exist'
        if ($isCrossDomainBlock) {
            Write-Result 'INFO' "WinRM to DC ($dcTarget) shows expected cross-domain Kerberos block -- NOT a real failure"
            Write-Host "         Error 0x8009030e is a Windows restriction on Negotiate auth to a foreign-domain DC." -ForegroundColor DarkGreen
            Write-Host "         Your credential is valid (AD auth passed). VM inventory connects directly to" -ForegroundColor DarkGreen
            Write-Host "         each VM by FQDN, not via the DC. Run Test-SingleServer.ps1 against a VM to confirm." -ForegroundColor DarkGreen
        } else {
            Write-Result 'WARN' "WinRM WARN -- $dcTarget" $wsmanResult.Detail
            Write-Host "         NOTE: WinRM to the domain FQDN tests DC reachability only." -ForegroundColor DarkGray
            Write-Host "               VM inventory connects to each VM by FQDN, not via the DC." -ForegroundColor DarkGray
        }
    }

    # Test 3: WinRM Invoke (actual remote execution)
    Write-Host "    Test 3/3: WinRM Invoke-Command..." -ForegroundColor Gray -NoNewline
    $invokeResult = Test-WinRMInvoke -Target $dcTarget -Cred $cred -IsPrimary $isPri
    Write-Host ""
    if ($invokeResult.OK) {
        if (-not $FailuresOnly) { Write-Result 'OK' "WinRM Invoke OK -- $dcTarget" $invokeResult.Detail }
    } else {
        $isCrossDomainBlock2 = $invokeResult.Detail -match '0x8009030e|8009030e|logon session does not exist|TrustedHosts|implicit credentials'
        if ($isCrossDomainBlock2) {
            Write-Result 'INFO' "WinRM Invoke to DC ($dcTarget) -- expected cross-domain restriction, not a VM connectivity failure"
            Write-Host "         Use Test-SingleServer.ps1 -Target VMNAME.$domFQDN to verify a specific VM." -ForegroundColor DarkGreen
        } else {
            Write-Result 'WARN' "WinRM Invoke WARN -- $dcTarget" $invokeResult.Detail
            Write-Host "         NOTE: VM inventory connects to each VM by FQDN, not via the DC." -ForegroundColor DarkGray
            Write-Host "               This warning does NOT necessarily mean VM collection will fail." -ForegroundColor DarkGray
        }
    }
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
if ($overallPass) {
    Write-Host "  RESULT: All AD authentications passed." -ForegroundColor Green
} else {
    Write-Host "  RESULT: One or more AD authentications FAILED." -ForegroundColor Red
    Write-Host "  Machines in failed domains will show ADError in the report." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "  TIP: To test against a specific VM instead of the DC:" -ForegroundColor DarkGray
Write-Host "    .\Test-Credentials.ps1 -Domain overheaddoor.com -DCName VMNAME.overheaddoor.com" -ForegroundColor DarkGray
Write-Host ""
}

