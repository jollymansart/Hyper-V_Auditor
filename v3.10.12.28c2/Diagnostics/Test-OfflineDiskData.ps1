<#
.SYNOPSIS
    Test-OfflineDiskData.ps1 - Diagnose DiskNumber deserialization for VM-Offline-Disks tab
    
.DESCRIPTION
    This script runs the exact same Get-Disk scriptblock used by the Hyper-V Inventory Report
    on a target VM (via WinRM or PSDirect) and inspects the returned data structure to diagnose
    why DiskNumber comes back as $null after deserialization on some VMs.
    
    Tests:
    1. Direct remote Get-Disk (raw objects)
    2. Hashtable return (same as report scriptblock)
    3. PSCustomObject return (alternative approach)
    4. Type inspection of deserialized DiskNumber values
    
.PARAMETER HostName
    Hyper-V host FQDN

.PARAMETER VMName
    VM display name to test

.PARAMETER Credential
    Credential for WinRM connection to the VM

.EXAMPLE
    $cred = Import-Clixml 'C:\ProgramData\S\HyperV-Cred.xml'
    .\Test-OfflineDiskData.ps1 -HostName RICTX-UCSHV-P7.ohdc.com -VMName PRD-System_Center_7-RITSCVMMP01 -Credential $cred
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$HostName = "RICTX-UCSHV-P7.ohdc.com",
    [Parameter(Mandatory)] [string]$VMName = "PRD-System_Center_7-RITSCVMMP01",
    [Parameter(Mandatory)] [PSCredential]$Credential = $cred
)

Write-Host "`n===== Step 1: Get VM Info from Host =====" -ForegroundColor Cyan
$vmInfo = Invoke-Command -ComputerName $HostName -Credential $Credential -ScriptBlock {
    param($name)
    $vm = Get-VM -Name $name -ErrorAction SilentlyContinue
    if ($vm) {
        @{ Name = $vm.Name; VMId = $vm.Id.ToString(); State = $vm.State.ToString() }
    }
} -ArgumentList $VMName

if (-not $vmInfo) {
    Write-Host "  VM '$VMName' not found on $HostName" -ForegroundColor Red
    return
}
Write-Host "  VM: $($vmInfo.Name)  State: $($vmInfo.State)  VMId: $($vmInfo.VMId)" -ForegroundColor Green

# Resolve a target for WinRM
$vmTarget = $VMName
# Try DNS
try {
    $dns = [System.Net.Dns]::GetHostEntry($VMName)
    if ($dns.HostName -match '\.') { $vmTarget = $dns.HostName }
} catch {}
# Try IP from host
$vmIP = Invoke-Command -ComputerName $HostName -Credential $Credential -ScriptBlock {
    param($name)
    $nic = Get-VM -Name $name | Get-VMNetworkAdapter -ErrorAction SilentlyContinue
    $ips = @($nic.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -ne '127.0.0.1' })
    if ($ips.Count -gt 0) { $ips[0] } else { '' }
} -ArgumentList $VMName
Write-Host "  WinRM Target: $vmTarget  |  IP: $vmIP" -ForegroundColor Gray

Write-Host "`n===== Step 2: Remote Get-Disk (raw) =====" -ForegroundColor Cyan
$rawDisks = $null
$connTarget = $vmTarget
$connMethod = 'WinRM'
try {
    $rawDisks = Invoke-Command -ComputerName $connTarget -Credential $Credential -ErrorAction Stop -ScriptBlock {
        Get-Disk | Select-Object Number, FriendlyName, Size, IsOffline, OperationalStatus, BusType, PartitionStyle
    }
} catch {
    Write-Host "  WinRM to $connTarget failed: $($_.Exception.Message -replace '\r?\n.*','')" -ForegroundColor Yellow
    if ($vmIP) {
        try {
            $rawDisks = Invoke-Command -ComputerName $vmIP -Credential $Credential -Authentication Negotiate -ErrorAction Stop -ScriptBlock {
                Get-Disk | Select-Object Number, FriendlyName, Size, IsOffline, OperationalStatus, BusType, PartitionStyle
            }
            $connTarget = $vmIP
        } catch {
            Write-Host "  WinRM to IP $vmIP also failed" -ForegroundColor Yellow
        }
    }
    # Try PSDirect
    if (-not $rawDisks) {
        Write-Host "  Trying PSDirect..." -ForegroundColor Yellow
        $connMethod = 'PSDirect'
        try {
            $rawDisks = Invoke-Command -ComputerName $HostName -Credential $Credential -ScriptBlock {
                param($vmId, $cred)
                Invoke-Command -VMId ([guid]$vmId) -Credential $cred -ScriptBlock {
                    Get-Disk | Select-Object Number, FriendlyName, Size, IsOffline, OperationalStatus, BusType, PartitionStyle
                }
            } -ArgumentList $vmInfo.VMId, $Credential
        } catch {
            Write-Host "  PSDirect also failed: $($_.Exception.Message -replace '\r?\n.*','')" -ForegroundColor Red
            return
        }
    }
}

Write-Host "  Connected via: $connMethod -> $connTarget" -ForegroundColor Green
Write-Host "  Total disks: $(@($rawDisks).Count)" -ForegroundColor Gray
foreach ($d in $rawDisks) {
    $offline = if ($d.IsOffline) { 'OFFLINE' } else { 'Online' }
    Write-Host "    Disk $($d.Number) | $($d.FriendlyName) | $([math]::Round($d.Size/1GB))GB | $offline | $($d.OperationalStatus) | $($d.BusType)" -ForegroundColor $(if ($d.IsOffline) { 'Yellow' } else { 'Gray' })
}

Write-Host "`n===== Step 3: Hashtable Return (report scriptblock) =====" -ForegroundColor Cyan
$scriptBlock = {
    try {
        $allDisks = Get-Disk -ErrorAction Stop
        $offlineDisks = @($allDisks | Where-Object { $_.IsOffline -eq $true -or $_.OperationalStatus -ne 'Online' })
        @{
            TotalDiskCount   = $allDisks.Count
            OfflineDisks     = @($offlineDisks | ForEach-Object {
                @{
                    DiskNumber        = $_.Number
                    FriendlyName      = $_.FriendlyName
                    SizeGB            = [math]::Round($_.Size / 1GB, 2)
                    PartitionStyle    = $_.PartitionStyle.ToString()
                    OperationalStatus = $_.OperationalStatus.ToString()
                    HealthStatus      = $_.HealthStatus.ToString()
                    IsOffline         = $_.IsOffline
                    IsReadOnly        = $_.IsReadOnly
                    OfflineReason     = if ($_.OfflineReason) { $_.OfflineReason.ToString() } else { '' }
                    BusType           = $_.BusType.ToString()
                }
            })
        }
    } catch {
        @{ TotalDiskCount = -1; OfflineDisks = @(); Error = $_.Exception.Message }
    }
}

$hashResult = $null
if ($connMethod -eq 'PSDirect') {
    $hashResult = Invoke-Command -ComputerName $HostName -Credential $Credential -ScriptBlock {
        param($vmId, $cred, $sb)
        Invoke-Command -VMId ([guid]$vmId) -Credential $cred -ScriptBlock ([scriptblock]::Create($sb))
    } -ArgumentList $vmInfo.VMId, $Credential, $scriptBlock.ToString()
} else {
    $hashResult = Invoke-Command -ComputerName $connTarget -Credential $Credential -Authentication Negotiate -ErrorAction SilentlyContinue -ScriptBlock $scriptBlock
    if (-not $hashResult) {
        $hashResult = Invoke-Command -ComputerName $connTarget -Credential $Credential -ErrorAction Stop -ScriptBlock $scriptBlock
    }
}

Write-Host "  Result type: $($hashResult.GetType().FullName)" -ForegroundColor Gray
Write-Host "  TotalDiskCount: $($hashResult.TotalDiskCount)" -ForegroundColor Gray
Write-Host "  OfflineDisks count: $($hashResult.OfflineDisks.Count)" -ForegroundColor Gray

foreach ($disk in $hashResult.OfflineDisks) {
    $diskType = $disk.GetType().FullName
    Write-Host "`n  --- Disk entry ---" -ForegroundColor Cyan
    Write-Host "    Object type:      $diskType" -ForegroundColor Gray
    
    # Test EVERY access method for DiskNumber
    $method1 = $disk.DiskNumber
    $method2 = $disk['DiskNumber']
    $method3 = $null
    try { $method3 = $disk.Item('DiskNumber') } catch {}
    $method4 = $null
    if ($disk -is [hashtable]) {
        $method4 = $disk.DiskNumber
    }
    # Try enumerating keys
    $keys = @()
    try {
        if ($disk.Keys) { $keys = @($disk.Keys) }
    } catch {
        try { $keys = @($disk.PSObject.Properties.Name) } catch {}
    }
    
    Write-Host "    .DiskNumber:      '$method1' (type: $(if ($null -ne $method1) { $method1.GetType().FullName } else { 'NULL' }))" -ForegroundColor $(if ($null -ne $method1) { 'Green' } else { 'Red' })
    Write-Host "    ['DiskNumber']:   '$method2' (type: $(if ($null -ne $method2) { $method2.GetType().FullName } else { 'NULL' }))" -ForegroundColor $(if ($null -ne $method2) { 'Green' } else { 'Red' })
    Write-Host "    .Item():          '$method3' (type: $(if ($null -ne $method3) { $method3.GetType().FullName } else { 'NULL' }))" -ForegroundColor $(if ($null -ne $method3) { 'Green' } else { 'Red' })
    Write-Host "    Available keys:   $($keys -join ', ')" -ForegroundColor Gray
    Write-Host "    .SizeGB:          $($disk.SizeGB)" -ForegroundColor Gray
    Write-Host "    .BusType:         $($disk.BusType)" -ForegroundColor Gray
    Write-Host "    .OfflineReason:   $($disk.OfflineReason)" -ForegroundColor Gray
    
    # Check if key exists but value is 0 (which PowerShell treats as $false/$null in some contexts)
    if ($keys -contains 'DiskNumber') {
        $rawVal = $disk['DiskNumber']
        Write-Host "    KEY EXISTS! Raw value: '$rawVal' | Is zero: $($rawVal -eq 0) | Is null: $($null -eq $rawVal)" -ForegroundColor Yellow
    }
}

Write-Host "`n===== Step 4: PSCustomObject Return (alternative) =====" -ForegroundColor Cyan
$altScriptBlock = {
    try {
        $allDisks = Get-Disk -ErrorAction Stop
        $offlineDisks = @($allDisks | Where-Object { $_.IsOffline -eq $true -or $_.OperationalStatus -ne 'Online' })
        @{
            TotalDiskCount   = $allDisks.Count
            OfflineDisks     = @($offlineDisks | ForEach-Object {
                [PSCustomObject]@{
                    DiskNumber        = [int]$_.Number
                    FriendlyName      = $_.FriendlyName
                    SizeGB            = [math]::Round($_.Size / 1GB, 2)
                    PartitionStyle    = $_.PartitionStyle.ToString()
                    OperationalStatus = $_.OperationalStatus.ToString()
                    IsOffline         = $_.IsOffline
                    BusType           = $_.BusType.ToString()
                    OfflineReason     = if ($_.OfflineReason) { $_.OfflineReason.ToString() } else { '' }
                }
            })
        }
    } catch {
        @{ TotalDiskCount = -1; OfflineDisks = @(); Error = $_.Exception.Message }
    }
}

$altResult = $null
if ($connMethod -eq 'PSDirect') {
    $altResult = Invoke-Command -ComputerName $HostName -Credential $Credential -ScriptBlock {
        param($vmId, $cred, $sb)
        Invoke-Command -VMId ([guid]$vmId) -Credential $cred -ScriptBlock ([scriptblock]::Create($sb))
    } -ArgumentList $vmInfo.VMId, $Credential, $altScriptBlock.ToString()
} else {
    $altResult = Invoke-Command -ComputerName $connTarget -Credential $Credential -Authentication Negotiate -ErrorAction SilentlyContinue -ScriptBlock $altScriptBlock
    if (-not $altResult) {
        $altResult = Invoke-Command -ComputerName $connTarget -Credential $Credential -ErrorAction Stop -ScriptBlock $altScriptBlock
    }
}

Write-Host "  PSCustomObject approach:" -ForegroundColor Gray
foreach ($disk in $altResult.OfflineDisks) {
    $diskType = $disk.GetType().FullName
    $dn = $disk.DiskNumber
    Write-Host "    Disk $dn | Type: $diskType | .DiskNumber type: $(if ($null -ne $dn) { $dn.GetType().FullName } else { 'NULL' }) | SizeGB: $($disk.SizeGB)" -ForegroundColor $(if ($null -ne $dn) { 'Green' } else { 'Red' })
}

Write-Host "`n===== Summary =====" -ForegroundColor Cyan
$hashDN = @($hashResult.OfflineDisks | ForEach-Object { $_.DiskNumber } | Where-Object { $null -ne $_ })
$altDN  = @($altResult.OfflineDisks | ForEach-Object { $_.DiskNumber } | Where-Object { $null -ne $_ })
Write-Host "  Hashtable approach: $($hashDN.Count)/$($hashResult.OfflineDisks.Count) DiskNumbers populated" -ForegroundColor $(if ($hashDN.Count -eq $hashResult.OfflineDisks.Count) { 'Green' } else { 'Yellow' })
Write-Host "  PSCustomObject approach: $($altDN.Count)/$($altResult.OfflineDisks.Count) DiskNumbers populated" -ForegroundColor $(if ($altDN.Count -eq $altResult.OfflineDisks.Count) { 'Green' } else { 'Yellow' })

if ($hashDN.Count -lt $hashResult.OfflineDisks.Count -and $altDN.Count -eq $altResult.OfflineDisks.Count) {
    Write-Host "`n  DIAGNOSIS: Hashtable deserialization loses DiskNumber." -ForegroundColor Yellow
    Write-Host "  FIX: Change offlineDiskScriptBlock to use [PSCustomObject]@{} instead of @{}" -ForegroundColor Yellow
    Write-Host "  Or: Cast DiskNumber to [int] in the hashtable: DiskNumber = [int]`$_.Number" -ForegroundColor Yellow
}
elseif ($hashDN.Count -lt $hashResult.OfflineDisks.Count) {
    Write-Host "`n  DIAGNOSIS: Both approaches lose DiskNumber. Check if `$_.Number is 0 for these disks." -ForegroundColor Red
    Write-Host "  Disk 0 is typically the boot disk. PowerShell may be treating 0 as `$null." -ForegroundColor Yellow
}
else {
    Write-Host "`n  Both approaches work on this VM. Issue may be VM-specific." -ForegroundColor Green
}
Write-Host ""
