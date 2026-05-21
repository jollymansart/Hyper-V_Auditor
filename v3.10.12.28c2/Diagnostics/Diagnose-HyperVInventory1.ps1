<#
.SYNOPSIS
    Hyper-V Inventory Diagnostic Tool v3.0

.DESCRIPTION
    Comprehensive diagnostics for the Hyper-V Inventory module.
    Run this BEFORE the report to identify and fix issues, or AFTER to investigate failures.
    
    Tests:
    - PowerShell prerequisites (modules, versions)
    - CredSSP configuration
    - AD discovery (hosts and clusters)
    - Per-host connectivity with detailed error classification
    - Cluster connectivity
    - Sample data collection from one host (validates the full pipeline)

.PARAMETER Credential
    PSCredential for remote hosts. If not provided, prompts or loads from saved file.

.PARAMETER OutputPath
    Path for diagnostic report. Defaults to desktop.

.PARAMETER QuickMode
    Skip the per-host deep tests and sample collection. Just checks prerequisites + AD.

.EXAMPLE
    .\Diagnose-HyperVInventory.ps1
    # Full diagnostics with credential prompt

.EXAMPLE
    $cred = Import-Clixml "C:\ProgramData\S\HyperV-Cred.xml"
    .\Diagnose-HyperVInventory.ps1 -Credential $cred -QuickMode
    # Quick prerequisite check only

.NOTES
    Author: Michael George
    Date: February 17, 2026
#>

param(
    [PSCredential]$Credential,
    [string]$OutputPath,
    [switch]$QuickMode
)

# ==============================================================
# HELPERS
# ==============================================================
$script:Results = [System.Collections.Generic.List[object]]::new()
$script:Errors  = [System.Collections.Generic.List[object]]::new()

function Write-Diag {
    param(
        [string]$Test,
        [ValidateSet('PASS','FAIL','WARN','INFO','SKIP')]
        [string]$Status,
        [string]$Message,
        [string]$Detail = '',
        [string]$Fix = ''
    )
    
    $color = switch ($Status) {
        'PASS' { 'Green' }
        'FAIL' { 'Red' }
        'WARN' { 'Yellow' }
        'INFO' { 'Cyan' }
        'SKIP' { 'Gray' }
    }
    
    $icon = switch ($Status) {
        'PASS' { '[+]' }
        'FAIL' { '[X]' }
        'WARN' { '[!]' }
        'INFO' { '[i]' }
        'SKIP' { '[-]' }
    }
    
    Write-Host "  $icon " -ForegroundColor $color -NoNewline
    Write-Host "$Test" -ForegroundColor White -NoNewline
    Write-Host " - " -NoNewline
    Write-Host $Message -ForegroundColor $color
    
    if ($Detail) { Write-Host "      $Detail" -ForegroundColor Gray }
    if ($Fix -and $Status -in @('FAIL','WARN')) { Write-Host "      FIX: $Fix" -ForegroundColor Yellow }
    
    $script:Results.Add([PSCustomObject]@{
        Test    = $Test
        Status  = $Status
        Message = $Message
        Detail  = $Detail
        Fix     = $Fix
    })
    
    if ($Status -eq 'FAIL') {
        $script:Errors.Add([PSCustomObject]@{
            Test    = $Test
            Message = $Message
            Fix     = $Fix
        })
    }
}

function Write-Section { 
    param([string]$Title)
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor DarkCyan
}

# ==============================================================
# CREDENTIAL SETUP
# ==============================================================
if (-not $Credential) {
    $credPath = "C:\ProgramData\S\HyperV-Cred.xml"
    if (Test-Path $credPath) {
        Write-Host "Loading saved credentials from $credPath..." -ForegroundColor Gray
        $Credential = Import-Clixml $credPath
    }
    else {
        $Credential = Get-Credential -Message "Enter domain admin credentials (ohdc\!mgeorge-adm)"
    }
}

Write-Host ""
Write-Host "  HYPER-V INVENTORY DIAGNOSTIC TOOL v3.0" -ForegroundColor White
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "  Running as: $($Credential.UserName)" -ForegroundColor Gray
Write-Host ""

# ==============================================================
# SECTION 1: PREREQUISITES
# ==============================================================
Write-Section "1. PREREQUISITES"

# PowerShell version
$psVer = $PSVersionTable.PSVersion
if ($psVer.Major -ge 5) {
    Write-Diag -Test "PowerShell Version" -Status PASS -Message "$($psVer.ToString())"
} else {
    Write-Diag -Test "PowerShell Version" -Status FAIL -Message "$($psVer.ToString()) (need 5.0+)" `
        -Fix "Upgrade to PowerShell 5.1 or later"
}

# Active Directory module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Diag -Test "ActiveDirectory Module" -Status PASS -Message "Loaded"
} catch {
    Write-Diag -Test "ActiveDirectory Module" -Status FAIL -Message "Not available" `
        -Fix "Install RSAT: Install-WindowsFeature RSAT-AD-PowerShell"
}

# FailoverClusters module
try {
    Import-Module FailoverClusters -ErrorAction Stop
    $fcVer = (Get-Module FailoverClusters).Version
    Write-Diag -Test "FailoverClusters Module" -Status PASS -Message "Version $fcVer"
    
    # Check if -Domain param exists on Get-Cluster
    $hasDomainParam = (Get-Command Get-Cluster -Module FailoverClusters).Parameters.ContainsKey('Domain')
    if ($hasDomainParam) {
        Write-Diag -Test "Get-Cluster -Domain param" -Status INFO -Message "Available (newer module)"
    } else {
        Write-Diag -Test "Get-Cluster -Domain param" -Status INFO -Message "Not available (v3.0 handles this)"
    }
} catch {
    Write-Diag -Test "FailoverClusters Module" -Status WARN -Message "Not available" `
        -Detail "Cluster discovery will be skipped" `
        -Fix "Install RSAT: Install-WindowsFeature RSAT-Clustering-PowerShell"
}

# ImportExcel module
try {
    Import-Module ImportExcel -ErrorAction Stop
    $ieVer = (Get-Module ImportExcel).Version
    Write-Diag -Test "ImportExcel Module" -Status PASS -Message "Version $ieVer"
} catch {
    Write-Diag -Test "ImportExcel Module" -Status FAIL -Message "Not installed" `
        -Fix "Install-Module -Name ImportExcel -Scope CurrentUser"
}

# Hyper-V PowerShell (local)
$hvModule = Get-Module -ListAvailable Hyper-V -ErrorAction SilentlyContinue
if ($hvModule) {
    Write-Diag -Test "Hyper-V Module (local)" -Status PASS -Message "Available"
} else {
    Write-Diag -Test "Hyper-V Module (local)" -Status WARN -Message "Not installed locally" `
        -Detail "Remote Invoke-Command still works; local Get-VM won't" `
        -Fix "Install-WindowsFeature Hyper-V-PowerShell (or RSAT equivalent)"
}

# ==============================================================
# SECTION 2: CREDENTIALING & CREDSSP
# ==============================================================
Write-Section "2. CREDENTIALS & CREDSSP"

# Account lockout check
try {
    $adUser = Get-ADUser ($Credential.GetNetworkCredential().UserName) -Properties LockedOut, Enabled, PasswordExpired
    
    if ($adUser.LockedOut) {
        Write-Diag -Test "Account Lockout" -Status FAIL -Message "Account is LOCKED OUT" `
            -Fix "Unlock-ADAccount -Identity $($adUser.SamAccountName)"
    } else {
        Write-Diag -Test "Account Lockout" -Status PASS -Message "Not locked"
    }
    
    if (-not $adUser.Enabled) {
        Write-Diag -Test "Account Enabled" -Status FAIL -Message "Account is DISABLED"
    } else {
        Write-Diag -Test "Account Enabled" -Status PASS -Message "Enabled"
    }
    
    if ($adUser.PasswordExpired) {
        Write-Diag -Test "Password Expired" -Status FAIL -Message "Password is EXPIRED" `
            -Fix "Change password for $($adUser.SamAccountName)"
    } else {
        Write-Diag -Test "Password Expired" -Status PASS -Message "Password valid"
    }
} catch {
    Write-Diag -Test "AD Account Check" -Status FAIL -Message $_.Exception.Message
}

# CredSSP Client
try {
    $credsspClient = Get-WSManCredSSP 2>$null
    if ($credsspClient -and $credsspClient[0] -match "configured to allow delegating") {
        $delegates = ($credsspClient[0] -split 'following target\(s\): ')[1]
        Write-Diag -Test "CredSSP Client" -Status PASS -Message "Enabled" `
            -Detail "Delegates to: $delegates"
    } else {
        Write-Diag -Test "CredSSP Client" -Status WARN -Message "Not configured or restricted" `
            -Fix 'Enable-WSManCredSSP -Role Client -DelegateComputer "*.ohdc.com" -Force'
    }
} catch {
    Write-Diag -Test "CredSSP Client" -Status WARN -Message "Could not check: $($_.Exception.Message)" `
        -Fix 'Enable-WSManCredSSP -Role Client -DelegateComputer "*.ohdc.com" -Force'
}

# ==============================================================
# SECTION 3: ACTIVE DIRECTORY DISCOVERY
# ==============================================================
Write-Section "3. AD DISCOVERY"

# Discover Hyper-V hosts
$adHosts = @()
try {
    $computers = Get-ADComputer -Filter {OperatingSystem -like "*Server*"} `
        -Properties OperatingSystem, ServicePrincipalName, LastLogonDate, IPv4Address
    
    $adHosts = $computers | Where-Object {
        $_.ServicePrincipalName -match "Microsoft Virtual" -or 
        $_.OperatingSystem -like "*Hyper-V*"
    }
    
    Write-Diag -Test "Hyper-V Host Discovery" -Status PASS -Message "Found $($adHosts.Count) hosts"
    
    foreach ($h in $adHosts) {
        $stale = if ($h.LastLogonDate -and ((Get-Date) - $h.LastLogonDate).Days -gt 90) { " [STALE - $((Get-Date) - $h.LastLogonDate).Days)d since logon]" } else { "" }
        Write-Host "      $($h.Name.PadRight(20)) $($h.OperatingSystem)$stale" -ForegroundColor Gray
    }
} catch {
    Write-Diag -Test "Hyper-V Host Discovery" -Status FAIL -Message $_.Exception.Message
}

# Discover clusters
$adClusters = @()
try {
    $adClusters = Get-ADComputer -Filter {ServicePrincipalName -like "MSClusterVirtualServer/*"} `
        -Properties ServicePrincipalName, CN, DNSHostName, Description, LastLogonDate
    
    Write-Diag -Test "Cluster Discovery" -Status PASS -Message "Found $($adClusters.Count) cluster objects"
    
    foreach ($c in $adClusters) {
        Write-Host "      $($c.Name.PadRight(25)) $($c.DNSHostName)" -ForegroundColor Gray
    }
} catch {
    Write-Diag -Test "Cluster Discovery" -Status FAIL -Message $_.Exception.Message
}

# ==============================================================
# SECTION 4: HOST CONNECTIVITY (unless QuickMode)
# ==============================================================
if (-not $QuickMode) {
    Write-Section "4. HOST CONNECTIVITY"
    
    $hostResults = [System.Collections.Generic.List[object]]::new()
    
    foreach ($h in $adHosts) {
        $fqdn = $h.DNSHostName
        $name = $h.Name
        $hostResult = [PSCustomObject]@{
            Host     = $name
            FQDN     = $fqdn
            Ping     = $false
            WinRM    = $false
            CredSSP  = $false
            HyperV   = $false
            VMCount  = 0
            Error    = ''
            Category = ''
        }
        
        Write-Host "  Testing: $name..." -ForegroundColor White -NoNewline
        
        # Ping
        $ping = Test-Connection -ComputerName $fqdn -Count 1 -Quiet -ErrorAction SilentlyContinue
        if (-not $ping) {
            $hostResult.Error = "Not responding to ping"
            $hostResult.Category = "OFFLINE"
            Write-Host " OFFLINE" -ForegroundColor Red
            $hostResults.Add($hostResult)
            
            Write-Diag -Test "Host: $name" -Status FAIL -Message "Not responding to ping" `
                -Detail "FQDN: $fqdn" `
                -Fix "Verify host is powered on and network is reachable"
            continue
        }
        $hostResult.Ping = $true
        
        # WinRM (basic Kerberos)
        try {
            $sessionOpt = New-PSSessionOption -OperationTimeout 15000 -IdleTimeout 15000
            $null = Invoke-Command -ComputerName $fqdn -Credential $Credential -SessionOption $sessionOpt `
                -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
            $hostResult.WinRM = $true
        }
        catch {
            $errMsg = $_.Exception.Message
            $hostResult.Error = $errMsg
            
            if ($errMsg -match "Access is denied|Access denied") {
                $hostResult.Category = "AUTH_DENIED"
                Write-Host " AUTH DENIED" -ForegroundColor Red
                Write-Diag -Test "Host: $name" -Status FAIL -Message "Access denied" `
                    -Fix "Verify $($Credential.UserName) has admin rights on $name"
            }
            elseif ($errMsg -match "WinRM client cannot process|not trusted") {
                $hostResult.Category = "CREDSSP_FAIL"
                Write-Host " CREDSSP FAIL" -ForegroundColor Yellow
                Write-Diag -Test "Host: $name" -Status WARN -Message "CredSSP delegation rejected" `
                    -Fix "Run on $name`: Enable-WSManCredSSP -Role Server -Force"
            }
            elseif ($errMsg -match "WinRM cannot complete") {
                $hostResult.Category = "WINRM_DOWN"
                Write-Host " WINRM DOWN" -ForegroundColor Red
                Write-Diag -Test "Host: $name" -Status FAIL -Message "WinRM not responding" `
                    -Fix "Run on $name`: Enable-PSRemoting -Force; Set-Service WinRM -StartupType Automatic"
            }
            else {
                $hostResult.Category = "OTHER"
                Write-Host " ERROR" -ForegroundColor Red
                Write-Diag -Test "Host: $name" -Status FAIL -Message $errMsg
            }
            $hostResults.Add($hostResult)
            continue
        }
        
        # CredSSP test
        try {
            $null = Invoke-Command -ComputerName $fqdn -Credential $Credential `
                -Authentication CredSSP -SessionOption $sessionOpt `
                -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
            $hostResult.CredSSP = $true
        }
        catch {
            $hostResult.Category = "CREDSSP_FAIL"
            # WinRM works but CredSSP doesn't — still usable without double-hop
        }
        
        # Hyper-V check
        try {
            $vmCount = Invoke-Command -ComputerName $fqdn -Credential $Credential `
                -Authentication CredSSP -SessionOption $sessionOpt `
                -ScriptBlock { (Get-VM).Count } -ErrorAction Stop
            $hostResult.HyperV = $true
            $hostResult.VMCount = $vmCount
            
            $credsspNote = if ($hostResult.CredSSP) { "" } else { " (no CredSSP)" }
            Write-Host " OK - $vmCount VMs$credsspNote" -ForegroundColor Green
            Write-Diag -Test "Host: $name" -Status PASS `
                -Message "$vmCount VMs | Ping=OK WinRM=OK CredSSP=$($hostResult.CredSSP) HyperV=OK"
        }
        catch {
            if ($_.Exception.Message -match "Get-VMHost.*not recognized|Get-VM.*not recognized") {
                $hostResult.Category = "NO_HYPERV"
                Write-Host " NO HYPER-V ROLE" -ForegroundColor Yellow
                Write-Diag -Test "Host: $name" -Status WARN `
                    -Message "Hyper-V cmdlets not available" `
                    -Detail "Host is online but Hyper-V role may not be installed" `
                    -Fix "Verify Hyper-V role: Get-WindowsFeature Hyper-V -ComputerName $name"
            }
            else {
                $hostResult.Error = $_.Exception.Message
                $hostResult.Category = "HYPERV_ERROR"
                Write-Host " HYPER-V ERROR" -ForegroundColor Red
                Write-Diag -Test "Host: $name" -Status FAIL -Message $_.Exception.Message
            }
        }
        
        $hostResults.Add($hostResult)
    }
    
    # Host summary
    Write-Host ""
    $online = @($hostResults | Where-Object Ping).Count
    $hvOK   = @($hostResults | Where-Object HyperV).Count
    $totalVMs = ($hostResults | Measure-Object -Property VMCount -Sum).Sum
    
    Write-Host "  Host Summary: $online/$($adHosts.Count) online, $hvOK accessible with Hyper-V, $totalVMs total VMs" -ForegroundColor Cyan

    # ==============================================================
    # SECTION 5: CLUSTER CONNECTIVITY
    # ==============================================================
    Write-Section "5. CLUSTER CONNECTIVITY"
    
    $clusterResults = [System.Collections.Generic.List[object]]::new()
    
    foreach ($c in $adClusters) {
        $cName = $c.DNSHostName
        if (-not $cName) { $cName = $c.Name }
        $shortName = $c.Name
        
        Write-Host "  Testing: $shortName..." -ForegroundColor White -NoNewline
        
        $clResult = [PSCustomObject]@{
            Cluster   = $shortName
            FQDN      = $cName
            Status    = 'Unknown'
            Nodes     = ''
            NodeCount = 0
            Error     = ''
        }
        
        try {
            # Try FQDN first, then short name
            $cluster = $null
            try {
                $cluster = Get-Cluster -Name $cName -ErrorAction Stop
            }
            catch {
                $cluster = Get-Cluster -Name $shortName -ErrorAction Stop
            }
            
            $nodes = Get-ClusterNode -Cluster $cluster.Name -ErrorAction Stop
            $clResult.Status = 'Online'
            $clResult.Nodes = ($nodes | Select-Object -ExpandProperty Name) -join ', '
            $clResult.NodeCount = $nodes.Count
            
            Write-Host " OK - $($nodes.Count) nodes ($($clResult.Nodes))" -ForegroundColor Green
            Write-Diag -Test "Cluster: $shortName" -Status PASS -Message "$($nodes.Count) nodes" `
                -Detail $clResult.Nodes
        }
        catch {
            $errMsg = $_.Exception.Message
            $clResult.Status = 'Failed'
            $clResult.Error = $errMsg
            
            if ($errMsg -match "not found|cluster service is not running") {
                Write-Host " OFFLINE/REMOVED" -ForegroundColor Yellow
                Write-Diag -Test "Cluster: $shortName" -Status WARN -Message "Cluster not reachable" `
                    -Detail "May be decommissioned or cluster service stopped"
            }
            elseif ($errMsg -match "Access denied|not authorized") {
                Write-Host " ACCESS DENIED" -ForegroundColor Red
                Write-Diag -Test "Cluster: $shortName" -Status FAIL -Message "Access denied" `
                    -Fix "Grant $($Credential.UserName) cluster admin rights"
            }
            else {
                Write-Host " FAILED" -ForegroundColor Red
                Write-Diag -Test "Cluster: $shortName" -Status FAIL -Message $errMsg
            }
        }
        
        $clusterResults.Add($clResult)
    }

    # ==============================================================
    # SECTION 6: SAMPLE DATA COLLECTION
    # ==============================================================
    Write-Section "6. SAMPLE DATA COLLECTION"
    
    $sampleHost = $hostResults | Where-Object { $_.HyperV -and $_.VMCount -gt 0 } | 
        Sort-Object VMCount -Descending | Select-Object -First 1
    
    if ($sampleHost) {
        Write-Host "  Testing full pipeline on: $($sampleHost.Host) ($($sampleHost.VMCount) VMs)..." -ForegroundColor White
        
        try {
            $sessionOpt = New-PSSessionOption -OperationTimeout 60000 -IdleTimeout 60000
            $sampleData = Invoke-Command -ComputerName $sampleHost.FQDN -Credential $Credential `
                -Authentication CredSSP -SessionOption $sessionOpt -ScriptBlock {
                    $result = @{}
                    
                    # Host info
                    try {
                        $vmHost = Get-VMHost
                        $result.HostOK = $true
                        $result.CPUs = $vmHost.LogicalProcessorCount
                        $result.MemGB = [math]::Round($vmHost.MemoryCapacity / 1GB, 0)
                    }
                    catch { $result.HostOK = $false; $result.HostError = $_.Exception.Message }
                    
                    # Cluster
                    try {
                        $cluster = Get-Cluster -ErrorAction Stop
                        $result.ClusterName = $cluster.Name
                        $result.ClusterOK = $true
                    }
                    catch { $result.ClusterOK = $false }
                    
                    # VMs (first 3)
                    try {
                        $vms = Get-VM
                        $result.VMCount = $vms.Count
                        $result.SampleVMs = @($vms | Select-Object -First 3 | ForEach-Object {
                            @{ Name = $_.Name; State = $_.State.ToString(); CPUs = $_.ProcessorCount; Gen = $_.Generation }
                        })
                        $result.VMsOK = $true
                    }
                    catch { $result.VMsOK = $false; $result.VMError = $_.Exception.Message }
                    
                    # Storage
                    try {
                        $volumes = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.Size -gt 0 }
                        $result.VolumeCount = $volumes.Count
                        $result.StorageOK = $true
                    }
                    catch { $result.StorageOK = $false }
                    
                    # Firmware (host)
                    try {
                        $cs = Get-CimInstance Win32_ComputerSystem
                        $result.Manufacturer = $cs.Manufacturer
                        $result.Model = $cs.Model
                        $result.FirmwareOK = $true
                    }
                    catch { $result.FirmwareOK = $false }
                    
                    # KVP (Guest OS detection)
                    try {
                        $firstRunningVM = Get-VM | Where-Object State -eq 'Running' | Select-Object -First 1
                        if ($firstRunningVM) {
                            $kvp = Get-WmiObject -Namespace "root\virtualization\v2" `
                                -Query "SELECT GuestIntrinsicExchangeItems FROM Msvm_KvpExchangeComponent WHERE SystemName='$($firstRunningVM.Id)'" `
                                -ErrorAction SilentlyContinue
                            $result.KVPOK = ($kvp -ne $null)
                            $result.KVPVMName = $firstRunningVM.Name
                        }
                        else { $result.KVPOK = $false; $result.KVPNote = "No running VMs" }
                    }
                    catch { $result.KVPOK = $false; $result.KVPError = $_.Exception.Message }
                    
                    $result
                } -ErrorAction Stop
            
            # Report sample results
            if ($sampleData.HostOK) {
                Write-Diag -Test "Sample: Get-VMHost" -Status PASS `
                    -Message "$($sampleData.CPUs) CPUs, $($sampleData.MemGB) GB RAM"
            } else {
                Write-Diag -Test "Sample: Get-VMHost" -Status FAIL -Message $sampleData.HostError
            }
            
            if ($sampleData.ClusterOK) {
                Write-Diag -Test "Sample: Cluster" -Status PASS -Message "Member of: $($sampleData.ClusterName)"
            } else {
                Write-Diag -Test "Sample: Cluster" -Status INFO -Message "Standalone (not clustered)"
            }
            
            if ($sampleData.VMsOK) {
                Write-Diag -Test "Sample: Get-VM" -Status PASS -Message "$($sampleData.VMCount) VMs found"
                foreach ($sv in $sampleData.SampleVMs) {
                    Write-Host "      $($sv.Name) | $($sv.State) | $($sv.CPUs) vCPUs | Gen $($sv.Gen)" -ForegroundColor Gray
                }
            } else {
                Write-Diag -Test "Sample: Get-VM" -Status FAIL -Message $sampleData.VMError
            }
            
            if ($sampleData.StorageOK) {
                Write-Diag -Test "Sample: Storage" -Status PASS -Message "$($sampleData.VolumeCount) volumes"
            } else {
                Write-Diag -Test "Sample: Storage" -Status FAIL -Message "Get-Volume failed"
            }
            
            if ($sampleData.FirmwareOK) {
                Write-Diag -Test "Sample: Firmware" -Status PASS `
                    -Message "$($sampleData.Manufacturer) $($sampleData.Model)"
            } else {
                Write-Diag -Test "Sample: Firmware" -Status FAIL -Message "CIM query failed"
            }
            
            if ($sampleData.KVPOK) {
                Write-Diag -Test "Sample: KVP (Guest OS)" -Status PASS `
                    -Message "Working on VM: $($sampleData.KVPVMName)"
            } else {
                $kvpNote = if ($sampleData.KVPNote) { $sampleData.KVPNote } 
                           elseif ($sampleData.KVPError) { $sampleData.KVPError }
                           else { "KVP exchange not available" }
                Write-Diag -Test "Sample: KVP (Guest OS)" -Status WARN -Message $kvpNote `
                    -Detail "Guest OS detection may show blank for some VMs"
            }
        }
        catch {
            Write-Diag -Test "Sample Collection" -Status FAIL -Message $_.Exception.Message
        }
    }
    else {
        Write-Diag -Test "Sample Collection" -Status SKIP -Message "No accessible hosts with VMs found"
    }
}
else {
    Write-Host ""
    Write-Host "  Sections 4-6 skipped (QuickMode)" -ForegroundColor Gray
}

# ==============================================================
# SUMMARY
# ==============================================================
Write-Section "SUMMARY"

$passCount = @($script:Results | Where-Object Status -eq 'PASS').Count
$failCount = @($script:Results | Where-Object Status -eq 'FAIL').Count
$warnCount = @($script:Results | Where-Object Status -eq 'WARN').Count
$totalCount = $script:Results.Count

Write-Host "  Total tests: $totalCount" -ForegroundColor White
Write-Host "  Passed: $passCount" -ForegroundColor Green
Write-Host "  Warnings: $warnCount" -ForegroundColor Yellow
Write-Host "  Failed: $failCount" -ForegroundColor Red

if ($script:Errors.Count -gt 0) {
    Write-Host ""
    Write-Host "  FIXES NEEDED:" -ForegroundColor Red
    Write-Host "  $('-' * 50)" -ForegroundColor Red
    
    $fixNum = 1
    foreach ($err in $script:Errors) {
        Write-Host "  $fixNum. [$($err.Test)] $($err.Message)" -ForegroundColor Yellow
        if ($err.Fix) {
            Write-Host "     FIX: $($err.Fix)" -ForegroundColor Green
        }
        $fixNum++
    }
}
else {
    Write-Host ""
    Write-Host "  All checks passed! Ready to run inventory." -ForegroundColor Green
}

# Export results
if (-not $OutputPath) {
    $OutputPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "HyperV-Diagnostics_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
}

try {
    $script:Results | Export-Csv -Path $OutputPath -NoTypeInformation -Force
    Write-Host ""
    Write-Host "  Diagnostic report saved: $OutputPath" -ForegroundColor Cyan
}
catch {
    Write-Host "  Could not save report: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
