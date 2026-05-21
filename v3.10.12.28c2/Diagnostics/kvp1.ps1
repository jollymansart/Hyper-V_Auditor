$hvHost = 'RICTX-UCSHV-P1.ohdc.com'
Invoke-Command -ComputerName $hvHost -ScriptBlock {
    Get-VM | Where-Object State -eq 'Running' | ForEach-Object {
        $kvpData = @{}
        try {
            $kvpItems = $_.GetRelated('Msvm_KvpExchangeComponent').GuestIntrinsicExchangeItems
            if ($kvpItems) {
                foreach ($item in $kvpItems) {
                    $xml = [xml]$item
                    $kvpData[$xml.INSTANCE.PROPERTY[0].VALUE] = $xml.INSTANCE.PROPERTY[1].VALUE
                }
            }
        } catch {}
        $ips = ($_ | Select-Object -ExpandProperty NetworkAdapters | Select-Object -First 1).IPAddresses
        [PSCustomObject]@{
            VM       = $_.Name
            KVP_FQDN = $kvpData['FullyQualifiedDomainName']
            IPs      = ($ips -join ',')
        }
    }
} | Where-Object { $_.KVP_FQDN -and $_.KVP_FQDN -notmatch 'ohdc\.com' } |
    Format-Table -AutoSize



Invoke-Command -ComputerName 'RICTX-UCSHV-P1.ohdc.com' -ScriptBlock {
    # Check ALL Hyper-V logs for any event mentioning power/start/stop/shutdown
    $logs = Get-WinEvent -ListLog 'Microsoft-Windows-Hyper-V-*' -ErrorAction SilentlyContinue |
        Where-Object { $_.RecordCount -gt 0 }
    
    $results = foreach ($log in $logs) {
        $events = Get-WinEvent -LogName $log.LogName -MaxEvents 50 -ErrorAction SilentlyContinue
        foreach ($evt in $events) {
            if ($evt.Message -match 'start|stop|shutdown|power|turned off|turned on|state change|reset|saved|paused') {
                [PSCustomObject]@{
                    LogName = $log.LogName
                    EventID = $evt.Id
                    Time    = $evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    Message = $evt.Message.Substring(0, [Math]::Min(150, $evt.Message.Length))
                }
            }
        }
    }
    $results | Sort-Object Time -Descending | Select-Object -First 30 |
        Format-Table LogName, EventID, Time, Message -AutoSize -Wrap
}




Invoke-Command -ComputerName 'RICTX-UCSHV-P1.ohdc.com' -ScriptBlock {
    # Check System log for VM-related events (User32 shutdowns, kernel power)
    $since = (Get-Date).AddDays(-30)
    
    # System log: shutdown/reboot events
    $sysEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        StartTime = $since
        Id        = @(1074, 6005, 6006, 6008, 6009, 41)
    } -MaxEvents 20 -ErrorAction SilentlyContinue
    
    Write-Output "=== System Log (shutdown/reboot events, last 30d) ==="
    if ($sysEvents) {
        $sysEvents | Select-Object Id, TimeCreated,
            @{N='Msg';E={$_.Message.Substring(0, [Math]::Min(120, $_.Message.Length))}} |
            Format-Table -AutoSize -Wrap
    } else { Write-Output "  (none found)" }
    
    # VMMS Admin: go back 30 days and look for ANY event not in the known noise IDs
    Write-Output ""
    Write-Output "=== VMMS-Admin (excluding 16300/10103, last 30d) ==="
    $vmmsEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-Hyper-V-VMMS-Admin'
        StartTime = $since
    } -MaxEvents 500 -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -notin @(16300, 10103) }
    
    if ($vmmsEvents) {
        $vmmsEvents | Group-Object Id | Sort-Object Count -Descending |
            ForEach-Object {
                [PSCustomObject]@{
                    EventID = $_.Name
                    Count   = $_.Count
                    Sample  = $_.Group[0].Message.Substring(0, [Math]::Min(120, $_.Group[0].Message.Length))
                }
            } | Format-Table -AutoSize -Wrap
    } else { Write-Output "  (none found besides 16300/10103)" }
    
    # Worker-Admin: actual worker events (not Operational trace)
    Write-Output ""
    Write-Output "=== Worker-Admin (last 30d) ==="
    $workerEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-Hyper-V-Worker-Admin'
        StartTime = $since
    } -MaxEvents 200 -ErrorAction SilentlyContinue
    
    if ($workerEvents) {
        $workerEvents | Group-Object Id | Sort-Object Count -Descending |
            ForEach-Object {
                [PSCustomObject]@{
                    EventID = $_.Name
                    Count   = $_.Count
                    Sample  = $_.Group[0].Message.Substring(0, [Math]::Min(120, $_.Group[0].Message.Length))
                }
            } | Format-Table -AutoSize -Wrap
    } else { Write-Output "  (none found)" }
    
    # FailoverClustering: live migration and resource movement
    Write-Output ""
    Write-Output "=== FailoverClustering/Operational (migration/failover, last 30d) ==="
    $fcEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-FailoverClustering/Operational'
        StartTime = $since
    } -MaxEvents 200 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'migrat|move|failover|offline|online' }
    
    if ($fcEvents) {
        $fcEvents | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 10 |
            ForEach-Object {
                [PSCustomObject]@{
                    EventID = $_.Name
                    Count   = $_.Count
                    Sample  = $_.Group[0].Message.Substring(0, [Math]::Min(120, $_.Group[0].Message.Length))
                }
            } | Format-Table -AutoSize -Wrap
    } else { Write-Output "  (none found)" }
}

# Find which host has RICTX-DMZWEB-P6
Invoke-Command -ComputerName 'RICTX-UCSHV-P1.ohdc.com','RICTX-UCSHV-P2.ohdc.com','RICTX-UCSHV-P6.ohdc.com','RICTX-UCSHV-P7.ohdc.com','RICTX-UCSHV-P8.ohdc.com' -ScriptBlock {
    $vm = Get-VM -Name 'RICTX-DMZWEB-P6' -ErrorAction SilentlyContinue
    if ($vm) { "FOUND on $env:COMPUTERNAME -- State: $($vm.State)" }
} -ErrorAction SilentlyContinue


# 1. Get KVP FQDNs for ALL VMs on RICTX-UCSHV-P8 (show cross-domain ones)
Invoke-Command -ComputerName 'RICTX-UCSHV-P8.ohdc.com' -ScriptBlock {
    Get-VM | Where-Object State -eq 'Running' | ForEach-Object {
        $kvpData = @{}
        try {
            $kvpItems = $_.GetRelated('Msvm_KvpExchangeComponent').GuestIntrinsicExchangeItems
            if ($kvpItems) {
                foreach ($item in $kvpItems) {
                    $xml = [xml]$item
                    $kvpData[$xml.INSTANCE.PROPERTY[0].VALUE] = $xml.INSTANCE.PROPERTY[1].VALUE
                }
            }
        } catch {}
        $ips = ($_ | Select-Object -ExpandProperty NetworkAdapters | Select-Object -First 1).IPAddresses
        [PSCustomObject]@{
            VM       = $_.Name
            KVP_FQDN = $kvpData['FullyQualifiedDomainName']
            Domain   = if ($kvpData['FullyQualifiedDomainName'] -match '\.(.+)$') { $Matches[1] } else { '(none)' }
            IPs      = ($ips -join ',')
        }
    }
} | Format-Table -AutoSize

PS C:\WINDOWS\system32> $cred = Import-Clixml 'C:\ProgramData\S\HyperV-Cred-overheaddoor.xml'
Invoke-Command -ComputerName 'RICTX-UCSHV-P8.ohdc.com' -ScriptBlock {
    param($GuestCred)
    Invoke-Command -VMName 'RICTX-DMZWEB-P06' -Credential $GuestCred -ScriptBlock {
        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            Domain       = (Get-CimInstance Win32_ComputerSystem).Domain
            FQDN         = ([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)).HostName
            OS           = (Get-CimInstance Win32_OperatingSystem).Caption
        }
    }
} -ArgumentList $cred


ComputerName   : RICTX-DMZWEB-P6
Domain         : overheaddoor.com
FQDN           : RICTX-DMZWEB-P6.overheaddoor.com
OS             : Microsoft Windows Server 2016 Datacenter
PSComputerName : RICTX-UCSHV-P8.ohdc.com
RunspaceId     : 84f3dc0f-ba19-4e49-9011-fe0dce8d98aa




$cred = Import-Clixml 'C:\ProgramData\S\HyperV-Cred.xml'
Invoke-Command -ComputerName 'RICTX-UCSHV-P1.ohdc.com' -ScriptBlock {
    param($GuestCred)
    $vm = Get-VM | Where-Object State -eq 'Running' | Where-Object { $_.Name -notmatch 'APPLIANCE|IPAM' } | Select-Object -First 1
    Write-Output "Testing PS Direct on: $($vm.Name)"
    Invoke-Command -VMName $vm.Name -Credential $GuestCred -ScriptBlock {
        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            Domain       = (Get-CimInstance Win32_ComputerSystem).Domain
            OS           = (Get-CimInstance Win32_OperatingSystem).Caption
        }
    }
} -ArgumentList $cred

# Find a Linux VM name from your environment (Oracle Linux, Ubuntu, etc.)
# Replace YOURLINUXVM with an actual Linux VM name
Invoke-Command -ComputerName 'MHOH-HV-P01.ohdc.com' -ScriptBlock {
    $linuxVMs = Get-VM | Where-Object { $_.State -eq 'Running' } |
        Where-Object { $_.Name -match 'LNX|LINUX|UBUNTU|ORACLE|RHEL|SLES' -or $_.Name -match 'nels' }
    if ($linuxVMs) {
        Write-Output "Linux VMs found: $(($linuxVMs | ForEach-Object { $_.Name }) -join ', ')"
    } else {
        Write-Output "No Linux VMs found by name pattern. Listing all running VMs:"
        Get-VM | Where-Object State -eq 'Running' | Select-Object Name | Format-Table -AutoSize
    }
}

# Quick check: which hosts have VMs that the report can't reach via WinRM?
# These are VMs that are Running but have no OSInfo (the 68 Warning VMs)
# We can approximate by checking which VMs DON'T resolve by short name
$hvHosts = @(
    'RICTX-UCSHV-P1.ohdc.com','RICTX-UCSHV-P2.ohdc.com',
    'RICTX-UCSHV-P6.ohdc.com','RICTX-UCSHV-P7.ohdc.com','RICTX-UCSHV-P8.ohdc.com'
)
Invoke-Command -ComputerName $hvHosts -ScriptBlock {
    $results = Get-VM | Where-Object State -eq 'Running' | ForEach-Object {
        $resolves = $false
        try { [System.Net.Dns]::GetHostEntry($_.Name) | Out-Null; $resolves = $true } catch {}
        [PSCustomObject]@{
            Host      = $env:COMPUTERNAME
            VM        = $_.Name
            Resolves  = $resolves
        }
    }
    $noResolve = @($results | Where-Object { -not $_.Resolves })
    if ($noResolve.Count -gt 0) {
        Write-Output "$env:COMPUTERNAME : $($noResolve.Count) VMs don't resolve by short name"
        $noResolve | Select-Object VM | Format-Table -AutoSize
    } else {
        Write-Output "$env:COMPUTERNAME : All $(@($results).Count) VMs resolve OK"
    }
} -ErrorAction SilentlyContinue

