Function Test-HyperVHostPermissions
{
<#
.SYNOPSIS
    Test Hyper-V Host Permissions and Connectivity
    
.DESCRIPTION
    Diagnostic script to troubleshoot "Access Denied" errors.
    Tests:
    1. Network connectivity (ping)
    2. WinRM connectivity
    3. Kerberos authentication (current user)
    4. CredSSP authentication (with credentials)
    5. Hyper-V cmdlet access
    6. Permission levels
    
.PARAMETER HostName
    Hyper-V host FQDN to test
    
.PARAMETER Credential
    Admin credentials to test
    
.EXAMPLE
    # Test with current user (will likely fail with Access Denied)
    .\Test-HyperVHostPermissions.ps1 -HostName "MHOH-SECVID-P1.ohdc.com"
    
.EXAMPLE
    # Test with admin credentials (should work)
    $cred = Get-Credential  # Enter: ohdc\!mgeorge-adm
    .\Test-HyperVHostPermissions.ps1 -HostName "MHOH-SECVID-P1.ohdc.com" -Credential $cred
    
.NOTES
    Author: Michael George
    Date: February 12, 2026
    Purpose: Diagnose "Access Denied" errors
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$HostName,
    
    [Parameter(Mandatory=$false)]
    [PSCredential]$Credential
)

$ErrorActionPreference = 'Continue'

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "Hyper-V Host Permission Diagnostic" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "Target Host: $HostName" -ForegroundColor White
Write-Host "Current User: $env:USERDOMAIN\$env:USERNAME" -ForegroundColor White
if ($Credential) {
    Write-Host "Test Credential: $($Credential.UserName)" -ForegroundColor White
}
Write-Host ""

# Test 1: Network Connectivity
Write-Host "[TEST 1] Network Connectivity (Ping)" -ForegroundColor Yellow
try {
    $ping = Test-Connection -ComputerName $HostName -Count 1 -ErrorAction Stop
    Write-Host "  [OK] Host is reachable" -ForegroundColor Green
    Write-Host "      IP: $($ping.IPV4Address)" -ForegroundColor Gray
}
catch {
    Write-Host "  [FAIL] Host is not responding to ping" -ForegroundColor Red
    Write-Host "      Error: $($_.Exception.Message)" -ForegroundColor Gray
    exit 1
}

# Test 2: WinRM Connectivity
Write-Host ""
Write-Host "[TEST 2] WinRM Connectivity" -ForegroundColor Yellow
try {
    $winrm = Test-WSMan -ComputerName $HostName -ErrorAction Stop
    Write-Host "  [OK] WinRM is responding" -ForegroundColor Green
    Write-Host "      ProductVersion: $($winrm.ProductVersion)" -ForegroundColor Gray
}
catch {
    Write-Host "  [FAIL] WinRM is not accessible" -ForegroundColor Red
    Write-Host "      Error: $($_.Exception.Message)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  TROUBLESHOOTING:" -ForegroundColor Yellow
    Write-Host "    1. Verify WinRM service is running on $HostName" -ForegroundColor Gray
    Write-Host "    2. Check firewall allows WinRM (port 5985/5986)" -ForegroundColor Gray
    Write-Host "    3. Verify $HostName is in TrustedHosts or same domain" -ForegroundColor Gray
    exit 1
}

# Test 3: Kerberos Authentication (Current User)
Write-Host ""
Write-Host "[TEST 3] Kerberos Authentication (Current User: $env:USERDOMAIN\$env:USERNAME)" -ForegroundColor Yellow
try {
    $result = Invoke-Command -ComputerName $HostName -ScriptBlock { 
        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            CurrentUser = "$env:USERDOMAIN\$env:USERNAME"
            IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }
    } -ErrorAction Stop
    
    Write-Host "  [OK] Kerberos authentication successful" -ForegroundColor Green
    Write-Host "      Connected to: $($result.ComputerName)" -ForegroundColor Gray
    Write-Host "      Running as: $($result.CurrentUser)" -ForegroundColor Gray
    Write-Host "      Is Admin: $($result.IsAdmin)" -ForegroundColor $(if ($result.IsAdmin) { "Green" } else { "Red" })
    
    if (-not $result.IsAdmin) {
        Write-Host ""
        Write-Host "  [WARNING] You are NOT an administrator on $HostName" -ForegroundColor Red
        Write-Host "            This is why you're getting 'Access Denied' errors!" -ForegroundColor Red
        Write-Host "            You need to use admin credentials with -Credential parameter" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  [FAIL] Kerberos authentication failed" -ForegroundColor Red
    Write-Host "      Error: $($_.Exception.Message)" -ForegroundColor Gray
    
    if ($_.Exception.Message -like "*Access is denied*") {
        Write-Host ""
        Write-Host "  [DIAGNOSIS] ACCESS DENIED - Root Cause:" -ForegroundColor Red
        Write-Host "    Your current account ($env:USERDOMAIN\$env:USERNAME) does not have" -ForegroundColor Yellow
        Write-Host "    administrator privileges on $HostName" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  [SOLUTION] Use -Credential parameter with admin account:" -ForegroundColor Green
        Write-Host "    `$cred = Get-Credential  # Enter: ohdc\!mgeorge-adm" -ForegroundColor Gray
        Write-Host "    .\Test-HyperVHostPermissions.ps1 -HostName '$HostName' -Credential `$cred" -ForegroundColor Gray
    }
}

# Test 4: CredSSP Authentication (if Credential provided)
if ($Credential) {
    Write-Host ""
    Write-Host "[TEST 4] CredSSP Authentication (With Credentials: $($Credential.UserName))" -ForegroundColor Yellow
    
    # First check if CredSSP is enabled
    Write-Host "  Checking CredSSP configuration..." -ForegroundColor Gray
    try {
        $credsspStatus = Get-WSManCredSSP
        $clientEnabled = $credsspStatus -match "wsman/\*\.ohdc\.com"
        
        if ($clientEnabled) {
            Write-Host "    [OK] CredSSP Client is enabled" -ForegroundColor Green
        }
        else {
            Write-Host "    [WARNING] CredSSP Client is NOT enabled" -ForegroundColor Yellow
            Write-Host "              Run: Enable-WSManCredSSP -Role Client -DelegateComputer '*.ohdc.com' -Force" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "    [WARNING] Could not check CredSSP status" -ForegroundColor Yellow
    }
    
    Write-Host "  Testing CredSSP connection..." -ForegroundColor Gray
    try {
        $result = Invoke-Command -ComputerName $HostName -Credential $Credential -Authentication CredSSP -ScriptBlock { 
            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                CurrentUser = "$env:USERDOMAIN\$env:USERNAME"
                IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            }
        } -ErrorAction Stop
        
        Write-Host "  [OK] CredSSP authentication successful" -ForegroundColor Green
        Write-Host "      Connected to: $($result.ComputerName)" -ForegroundColor Gray
        Write-Host "      Running as: $($result.CurrentUser)" -ForegroundColor Gray
        Write-Host "      Is Admin: $($result.IsAdmin)" -ForegroundColor $(if ($result.IsAdmin) { "Green" } else { "Red" })
    }
    catch {
        Write-Host "  [FAIL] CredSSP authentication failed" -ForegroundColor Red
        Write-Host "      Error: $($_.Exception.Message)" -ForegroundColor Gray
        
        if ($_.Exception.Message -like "*user name and password when CredSSP*") {
            Write-Host ""
            Write-Host "  [INFO] This error is EXPECTED - it confirms CredSSP requires credentials" -ForegroundColor Cyan
        }
        elseif ($_.Exception.Message -like "*Access is denied*") {
            Write-Host ""
            Write-Host "  [DIAGNOSIS] Credential account does not have admin rights" -ForegroundColor Red
        }
    }
}

# Test 5: Hyper-V Cmdlet Access
Write-Host ""
Write-Host "[TEST 5] Hyper-V Cmdlet Access" -ForegroundColor Yellow

$testParams = @{
    ComputerName = $HostName
    ErrorAction = 'Stop'
}
if ($Credential) {
    $testParams['Credential'] = $Credential
    $testParams['Authentication'] = 'CredSSP'
}

try {
    $hvHost = Invoke-Command @testParams -ScriptBlock {
        Get-VMHost | Select-Object -Property ComputerName, LogicalProcessorCount, MemoryCapacity, VirtualMachinePath
    }
    
    Write-Host "  [OK] Hyper-V access successful" -ForegroundColor Green
    Write-Host "      Hyper-V Host: $($hvHost.ComputerName)" -ForegroundColor Gray
    Write-Host "      CPUs: $($hvHost.LogicalProcessorCount)" -ForegroundColor Gray
    Write-Host "      Memory: $([Math]::Round($hvHost.MemoryCapacity / 1GB, 2)) GB" -ForegroundColor Gray
    Write-Host "      VM Path: $($hvHost.VirtualMachinePath)" -ForegroundColor Gray
}
catch {
    Write-Host "  [FAIL] Cannot access Hyper-V cmdlets" -ForegroundColor Red
    Write-Host "      Error: $($_.Exception.Message)" -ForegroundColor Gray
}

# Test 6: Get VM List
Write-Host ""
Write-Host "[TEST 6] VM Enumeration" -ForegroundColor Yellow
try {
    $vms = Invoke-Command @testParams -ScriptBlock {
        Get-VM | Select-Object -First 5 -Property Name, State, CPUUsage, MemoryAssigned
    }
    
    if ($vms) {
        Write-Host "  [OK] Successfully retrieved VM list" -ForegroundColor Green
        Write-Host "      Found $(@($vms).Count) VMs (showing first 5):" -ForegroundColor Gray
        foreach ($vm in $vms) {
            Write-Host "        - $($vm.Name) ($($vm.State))" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "  [OK] Connection successful, but no VMs found" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  [FAIL] Cannot enumerate VMs" -ForegroundColor Red
    Write-Host "      Error: $($_.Exception.Message)" -ForegroundColor Gray
}

# Summary
Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

if ($Credential) {
    Write-Host "Recommendation: Use these parameters for inventory:" -ForegroundColor Green
    Write-Host ""
    Write-Host "  `$cred = Get-Credential  # Enter: $($Credential.UserName)" -ForegroundColor Gray
    Write-Host "  .\Invoke-HyperVInventoryReport-v2.0.ps1 ``" -ForegroundColor Gray
    Write-Host "      -OutputPath '...' ``" -ForegroundColor Gray
    Write-Host "      -Credential `$cred ``" -ForegroundColor Gray
    Write-Host "      -UseCredSSP ``" -ForegroundColor Gray
    Write-Host "      -Verbose" -ForegroundColor Gray
}
else {
    Write-Host "Next Step: Rerun this test with admin credentials:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  `$cred = Get-Credential  # Enter: ohdc\!mgeorge-adm" -ForegroundColor Gray
    Write-Host "  .\Test-HyperVHostPermissions.ps1 -HostName '$HostName' -Credential `$cred" -ForegroundColor Gray
}
Write-Host ""
}

