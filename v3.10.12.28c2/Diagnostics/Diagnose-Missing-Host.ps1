<#
.SYNOPSIS
    Diagnose Why MHOH-SECVID-P1 Disappeared from Inventory
    
.DESCRIPTION
    This host showed 58 VMs in the 15:03 run but is missing from the 17:56 run.
    This script will test connectivity and Hyper-V access.
    
.PARAMETER Credential
    Credentials for CredSSP authentication
    
.EXAMPLE
    $cred = Get-Credential
    .\Diagnose-Missing-Host.ps1 -Credential $cred
#>

param(
    [Parameter(Mandatory=$true)]
    [PSCredential]$Credential
)

$targetHost = "MHOH-SECVID-P1.ohdc.com"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Missing Host Diagnostic" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Target: $targetHost" -ForegroundColor White
Write-Host "Credential: $($Credential.UserName)" -ForegroundColor White
Write-Host ""

# Test 1: Ping
Write-Host "[TEST 1] Network connectivity (Ping)..." -NoNewline
try {
    $ping = Test-Connection -ComputerName $targetHost -Count 1 -Quiet -ErrorAction Stop
    if ($ping) {
        Write-Host " [PASS]" -ForegroundColor Green
    }
    else {
        Write-Host " [FAIL]" -ForegroundColor Red
        Write-Host "  Host is not responding to ping" -ForegroundColor Gray
    }
}
catch {
    Write-Host " [FAIL]" -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Gray
}

# Test 2: WinRM
Write-Host "[TEST 2] WinRM connectivity..." -NoNewline
try {
    $winrm = Test-WSMan -ComputerName $targetHost -ErrorAction Stop
    Write-Host " [PASS]" -ForegroundColor Green
}
catch {
    Write-Host " [FAIL]" -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Gray
}

# Test 3: Kerberos (no credential)
Write-Host "[TEST 3] Kerberos authentication (current user)..." -NoNewline
try {
    $session = New-PSSession -ComputerName $targetHost -ErrorAction Stop
    Write-Host " [PASS]" -ForegroundColor Green
    
    $result = Invoke-Command -Session $session -ScriptBlock {
        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            User = $env:USERNAME
            IsHyperV = (Get-WindowsFeature -Name Hyper-V).Installed
        }
    }
    
    Write-Host "    Computer: $($result.ComputerName)" -ForegroundColor Gray
    Write-Host "    User: $($result.User)" -ForegroundColor Gray
    Write-Host "    Hyper-V Installed: $($result.IsHyperV)" -ForegroundColor Gray
    
    Remove-PSSession -Session $session
}
catch {
    Write-Host " [FAIL]" -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Gray
}

# Test 4: CredSSP
Write-Host "[TEST 4] CredSSP authentication..." -NoNewline
try {
    $session = New-PSSession -ComputerName $targetHost -Credential $Credential -Authentication CredSSP -ErrorAction Stop
    Write-Host " [PASS]" -ForegroundColor Green
    
    $result = Invoke-Command -Session $session -ScriptBlock {
        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            User = $env:USERNAME
            IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }
    }
    
    Write-Host "    Computer: $($result.ComputerName)" -ForegroundColor Gray
    Write-Host "    User: $($result.User)" -ForegroundColor Gray
    Write-Host "    Is Admin: $($result.IsAdmin)" -ForegroundColor Gray
    
    Remove-PSSession -Session $session
}
catch {
    Write-Host " [FAIL]" -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Gray
}

# Test 5: Get-VMHost (Hyper-V access)
Write-Host "[TEST 5] Hyper-V host access..." -NoNewline
try {
    $session = New-PSSession -ComputerName $targetHost -Credential $Credential -Authentication CredSSP -ErrorAction Stop
    
    $hostInfo = Invoke-Command -Session $session -ScriptBlock {
        $vmHost = Get-VMHost -ErrorAction Stop
        [PSCustomObject]@{
            Name = $vmHost.Name
            LogicalProcessors = $vmHost.LogicalProcessorCount
            MemoryGB = [math]::Round($vmHost.MemoryCapacity / 1GB, 2)
        }
    }
    
    Write-Host " [PASS]" -ForegroundColor Green
    Write-Host "    Host: $($hostInfo.Name)" -ForegroundColor Gray
    Write-Host "    CPUs: $($hostInfo.LogicalProcessors)" -ForegroundColor Gray
    Write-Host "    Memory: $($hostInfo.MemoryGB) GB" -ForegroundColor Gray
    
    Remove-PSSession -Session $session
}
catch {
    Write-Host " [FAIL]" -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Gray
}

# Test 6: Get-VM (VM enumeration)
Write-Host "[TEST 6] VM enumeration..." -NoNewline
try {
    $session = New-PSSession -ComputerName $targetHost -Credential $Credential -Authentication CredSSP -ErrorAction Stop
    
    $vms = Invoke-Command -Session $session -ScriptBlock {
        Get-VM -ErrorAction Stop | Select-Object Name, State, CPUUsage, @{N='MemoryMB';E={$_.MemoryAssigned / 1MB}}
    }
    
    Write-Host " [PASS]" -ForegroundColor Green
    Write-Host "    Found: $($vms.Count) VMs" -ForegroundColor Cyan
    
    Write-Host ""
    Write-Host "    Sample VMs (first 10):" -ForegroundColor Gray
    foreach ($vm in ($vms | Select-Object -First 10)) {
        Write-Host "      - $($vm.Name) [$($vm.State)]" -ForegroundColor Gray
    }
    if ($vms.Count -gt 10) {
        Write-Host "      ... and $($vms.Count - 10) more" -ForegroundColor Gray
    }
    
    Remove-PSSession -Session $session
}
catch {
    Write-Host " [FAIL]" -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Gray
}

# Test 7: Check why it might have been filtered out
Write-Host ""
Write-Host "[TEST 7] Checking AD presence..." -NoNewline
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    
    $adComputer = Get-ADComputer -Identity "MHOH-SECVID-P1" -Properties OperatingSystem, ServicePrincipalName, DNSHostName, LastLogonDate -ErrorAction Stop
    
    Write-Host " [PASS]" -ForegroundColor Green
    Write-Host "    Name: $($adComputer.Name)" -ForegroundColor Gray
    Write-Host "    FQDN: $($adComputer.DNSHostName)" -ForegroundColor Gray
    Write-Host "    OS: $($adComputer.OperatingSystem)" -ForegroundColor Gray
    Write-Host "    Last Logon: $($adComputer.LastLogonDate)" -ForegroundColor Gray
    
    # Check SPN
    $hasHyperVSPN = $false
    if ($adComputer.ServicePrincipalName) {
        foreach ($spn in $adComputer.ServicePrincipalName) {
            if ($spn -like "*Microsoft Virtual*") {
                $hasHyperVSPN = $true
                Write-Host "    Hyper-V SPN: $spn" -ForegroundColor Green
            }
        }
    }
    
    if (-not $hasHyperVSPN) {
        Write-Host "    [WARNING] No Hyper-V SPN found!" -ForegroundColor Red
        Write-Host "    This host may not be detected by Get-HyperVHostsFromAD" -ForegroundColor Red
    }
}
catch {
    Write-Host " [FAIL]" -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "DIAGNOSTIC COMPLETE" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "TROUBLESHOOTING:" -ForegroundColor Yellow
Write-Host "  1. If ALL tests pass, host should be in inventory" -ForegroundColor White
Write-Host "  2. If Hyper-V SPN is missing, host won't be discovered" -ForegroundColor White
Write-Host "  3. If CredSSP fails, host will be skipped" -ForegroundColor White
Write-Host "  4. Check 'Unavailable-Hosts' worksheet in Excel report" -ForegroundColor White
Write-Host ""
