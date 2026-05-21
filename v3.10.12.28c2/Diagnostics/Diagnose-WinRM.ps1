<#
.SYNOPSIS
    Diagnoses the "no authentication flag" WinRM error seen in Run_Report.ps1
    credential precheck for non-primary domain credentials (overheaddoor.com).

.DESCRIPTION
    The Run_Report.ps1 precheck was testing WinRM using no authentication method
    when providing a credential, which causes this error:
    "The WinRM client could not process the request because credentials were
     specified along with the 'no authentication' flag."

    This script tests the CORRECT approach (Negotiate authentication) and shows
    which method works. It also tests WinRM against an actual VM (not the DC)
    which is a better test for what the inventory run actually does.

.EXAMPLE
    # Diagnose overheaddoor.com WinRM issues:
    .\Diagnose-WinRM.ps1 -CredFile "C:\ProgramData\S\HyperV-Cred-overheaddoor.xml" -Domain overheaddoor.com

    # Test against a specific VM:
    .\Diagnose-WinRM.ps1 -CredFile "C:\ProgramData\S\HyperV-Cred-overheaddoor.xml" -Target VMNAME.overheaddoor.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$CredFile,

    [string]$Domain = 'overheaddoor.com',
    [string]$Target = ''   # If blank, uses the domain FQDN (DC) as target
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'

if (-not (Test-Path $CredFile)) {
    Write-Host "Credential file not found: $CredFile" -ForegroundColor Red; return
}
$cred = Import-Clixml $CredFile
Write-Host ""
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host "  WINRM AUTHENTICATION DIAGNOSTIC" -ForegroundColor Cyan
Write-Host "  Domain  : $Domain" -ForegroundColor White
Write-Host "  User    : $($cred.UserName)" -ForegroundColor White
Write-Host "=======================================" -ForegroundColor Cyan

$testTarget = if ($Target) { $Target } else { $Domain }
Write-Host "  Target  : $testTarget ($(if ($Target) { 'VM/Server' } else { 'Domain FQDN/DC' }))" -ForegroundColor White
Write-Host ""
Write-Host "  NOTE: WinRM to the domain FQDN ($Domain) hits a DC." -ForegroundColor DarkGray
Write-Host "  The inventory connects directly to each VM by FQDN, not via the DC." -ForegroundColor DarkGray
Write-Host "  A WARN on the DC test does NOT mean VM collection will fail." -ForegroundColor DarkGray
Write-Host ""

# Test each authentication method
$methods = @(
    @{ Name = 'Default (BAD -- causes "no auth flag" error)'; Auth = 'Default';   UseCred = $true  },
    @{ Name = 'Negotiate (CORRECT for cross-domain)';        Auth = 'Negotiate'; UseCred = $true  },
    @{ Name = 'Kerberos (best if SPN is registered)';        Auth = 'Kerberos';  UseCred = $true  },
    @{ Name = 'No credential (current user -- should fail)'; Auth = 'Negotiate'; UseCred = $false }
)

foreach ($m in $methods) {
    Write-Host "  Testing: $($m.Name)" -ForegroundColor White
    try {
        $p = @{ ComputerName = $testTarget; ErrorAction = 'Stop'; Authentication = $m.Auth }
        if ($m.UseCred) { $p['Credential'] = $cred }
        $null = Test-WSMan @p
        Write-Host "    [PASS] Test-WSMan succeeded" -ForegroundColor Green
    } catch {
        $msg = ($_.Exception.Message -split '\r?\n')[0]
        Write-Host "    [FAIL] $msg" -ForegroundColor Red
    }
    Write-Host ""
}

# Now test Invoke-Command against the actual target
Write-Host "  ---- Invoke-Command test against: $testTarget ----" -ForegroundColor Cyan
foreach ($auth in @('Kerberos', 'Negotiate')) {
    Write-Host "  Auth: $auth" -ForegroundColor White
    try {
        $result = Invoke-Command -ComputerName $testTarget -Credential $cred -Authentication $auth -ErrorAction Stop -ScriptBlock {
            "$env:COMPUTERNAME | OS: $((Get-WmiObject Win32_OperatingSystem -EA SilentlyContinue).Caption) | PS: $($PSVersionTable.PSVersion)"
        }
        Write-Host "    [PASS] $result" -ForegroundColor Green
        break
    } catch {
        Write-Host "    [FAIL] $(($_.Exception.Message -split '\r?\n')[0])" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "  ---- SUMMARY ----" -ForegroundColor Cyan
Write-Host "  The 'WARN' in Run_Report.ps1 for overheaddoor.com is a FALSE alarm." -ForegroundColor Yellow
Write-Host "  The precheck was using 'Default' auth (wrong) instead of 'Negotiate'." -ForegroundColor Yellow
Write-Host "  The v3.5.3 fix uses Negotiate for cross-domain WinRM tests." -ForegroundColor Green
Write-Host "  Use Test-SingleServer.ps1 to confirm a specific overheaddoor.com VM works." -ForegroundColor Gray
Write-Host ""
