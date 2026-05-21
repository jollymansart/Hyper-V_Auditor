<#
.SYNOPSIS
    HyperV Inventory v3.2.9 - OS Detection & Application Inventory Module
    
.DESCRIPTION
    Functions for detecting OS type, version, and installed applications
    INCLUDES OPTIONAL APPLICATION INVENTORY (can be time-intensive!)
    
.NOTES
    Author: Michael George
    Version: 3.10.12-OS
    Date: March 10, 2026
#>

#Requires -Version 5.0

function Get-VMOperatingSystemInfo {
    <#
    .SYNOPSIS
        Gets detailed OS information from a VM
        
    .PARAMETER IncludeApplications
        OPTIONAL: Include application inventory (adds ~15 seconds per VM)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$VMName,
        
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeApplications,
        
        # Services filter (v3.4.1) - controls what StartModes are collected
        [Parameter(Mandatory=$false)]
        [string[]]$SvcCollectModes = @('Auto'),
        
        [Parameter(Mandatory=$false)]
        [string[]]$SvcExcludeNames = @(),

        # Scheduled tasks (v3.4.1 - S4b)
        [Parameter(Mandatory=$false)]
        [bool]$IncludeScheduledTasks = $true,

        [Parameter(Mandatory=$false)]
        [bool]$IncludeMicrosoftTasks = $false,

        [Parameter(Mandatory=$false)]
        [bool]$IncludeDisabledTasks = $false,

        # v3.10.5 CR84: WinRM authentication method override
        # 'Default' = Kerberos (standard). 'Negotiate' = NTLM fallback for cross-domain VMs.
        [Parameter(Mandatory=$false)]
        [ValidateSet('Default','Negotiate','Kerberos','CredSSP')]
        [string]$Authentication = 'Default'
    )
    
    Write-Verbose "Retrieving OS information for VM: $VMName"
    
    $osInfo = @{
        OSType = "Unknown"
        OSName = "Unknown"
        OSVersion = "Unknown"
        OSBuild = "Unknown"
        OSArchitecture = "Unknown"
        InstallDate = "Unknown"
        LastBootTime = "Unknown"
        ServicePack = "N/A"
        LicenseStatus = "Unknown"
        Domain = "Unknown"
        TimeZone = "Unknown"
        TimeZoneId = ""           # Windows TZID (e.g. "Eastern Standard Time") for comparison with SiteTimezones config
        TimeOffsetSeconds = $null # Offset from NTP server in seconds (w32tm /query /status)
        NTPSource = ""            # NTP time source hostname
        WindowsUpdateStatus = "Unknown"
        KernelVersion = "N/A"
        PackageCount = 0
        Applications = @()
        Error = $null
    }
    
    try {
        # Try to connect to the VM guest OS
        # v3.10.5 CR84: Build Invoke-Command params dynamically to support Authentication override
        $icParams = @{
            ComputerName = $VMName
            ErrorAction  = 'Stop'
        }
        if ($Credential) { $icParams['Credential'] = $Credential }
        if ($Authentication -ne 'Default') { $icParams['Authentication'] = $Authentication }

        $guestOS = Invoke-Command @icParams -ScriptBlock {
            $result = @{}
            
            # Try Windows first
            try {
                $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
                $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                
                $result.OSType = "Windows"
                $result.OSName = $os.Caption
                $result.OSVersion = $os.Version
                $result.OSBuild = $os.BuildNumber
                $result.OSArchitecture = $os.OSArchitecture
                $result.InstallDate = $os.InstallDate.ToString("yyyy-MM-dd")
                $result.LastBootTime = $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
                $result.ServicePack = if ($os.ServicePackMajorVersion -gt 0) { 
                    "SP$($os.ServicePackMajorVersion)" 
                } else { 
                    "N/A" 
                }
                $result.Domain = $computerSystem.Domain

                # Timezone: collect both DisplayName (human readable) and Id (Windows TZID for comparison)
                $tzObj = Get-TimeZone
                $result.TimeZone   = $tzObj.DisplayName
                $result.TimeZoneId = $tzObj.Id   # e.g. "Eastern Standard Time" -- matches SiteTimezones config

                # NTP time offset: query w32tm for current offset from time source.
                # TimeOffsetSeconds = positive = guest clock is ahead, negative = behind.
                try {
                    $w32Status = w32tm /query /status 2>$null
                    $offsetLine = $w32Status | Where-Object { $_ -match '^Time Source:|^Last Successful Sync Time:|^ClockRate:|^Stratum:|^Source:' }
                    # Parse "Time Source:" and offset from the verbose status output
                    $offsetLine2 = $w32Status | Where-Object { $_ -match 'Time Offset:' }
                    if ($offsetLine2) {
                        # Format: "Time Offset: 0.0000000s (Local)"
                        if ($offsetLine2 -match 'Time Offset:\s+([-\d.]+)s') {
                            $result.TimeOffsetSeconds = [math]::Round([double]$Matches[1], 3)
                        } else {
                            $result.TimeOffsetSeconds = $null
                        }
                    } else {
                        $result.TimeOffsetSeconds = $null
                    }
                    # Also capture the NTP source name
                    $ntpLine = $w32Status | Where-Object { $_ -match '^Source:' }
                    $result.NTPSource = if ($ntpLine) { ($ntpLine -replace '^Source:\s+','').Trim() } else { '' }
                }
                catch {
                    $result.TimeOffsetSeconds = $null
                    $result.NTPSource = ''
                }
                
                # License status
                try {
                    $license = Get-CimInstance -ClassName SoftwareLicensingProduct -ErrorAction SilentlyContinue | 
                        Where-Object { $_.PartialProductKey -and $_.Name -like "*Windows*" } | 
                        Select-Object -First 1
                    
                    $result.LicenseStatus = switch ($license.LicenseStatus) {
                        0 { "Unlicensed" }
                        1 { "Licensed" }
                        2 { "OOB Grace" }
                        3 { "OOT Grace" }
                        4 { "Non-Genuine Grace" }
                        5 { "Notification" }
                        default { "Unknown" }
                    }
                    
                    # Activation method detection (v3.2.0)
                    $result.ActivationMethod = 'Unknown'
                    $result.KMSServer = ''
                    $result.PartialKey = ''
                    if ($license) {
                        $result.PartialKey = if ($license.PartialProductKey) { $license.PartialProductKey } else { '' }
                        $desc = if ($license.Description) { $license.Description } else { '' }
                        if ($desc -match 'AVMA') {
                            $result.ActivationMethod = 'AVMA'
                        }
                        elseif ($desc -match 'KMS' -or $desc -match 'VOLUME_KMSCLIENT') {
                            $result.ActivationMethod = 'KMS'
                            $result.KMSServer = if ($license.DiscoveredKeyManagementServiceMachineName) { 
                                $license.DiscoveredKeyManagementServiceMachineName 
                            } elseif ($license.KeyManagementServiceMachine) {
                                $license.KeyManagementServiceMachine
                            } else { '' }
                        }
                        elseif ($desc -match 'MAK') {
                            $result.ActivationMethod = 'MAK'
                        }
                        elseif ($desc -match 'RETAIL') {
                            $result.ActivationMethod = 'Retail'
                        }
                        elseif ($license.LicenseStatus -eq 1) {
                            $result.ActivationMethod = 'Activated (Method Unknown)'
                        }
                    }
                }
                catch {
                    $result.LicenseStatus = "Unknown"
                    $result.ActivationMethod = 'Unknown'
                    $result.KMSServer = ''
                    $result.PartialKey = ''
                }
                
                # Windows Update status (optional - can be slow)
                $result.WindowsUpdateStatus = "Not Checked"
                
                # Last Windows Update (Get-HotFix - fast, built-in)
                $result.LastUpdateKB = 'N/A'
                $result.LastUpdateDate = 'N/A'
                try {
                    $lastHF = Get-HotFix -ErrorAction Stop | 
                        Where-Object { $_.InstalledOn } |
                        Sort-Object InstalledOn -Descending | 
                        Select-Object -First 1
                    if ($lastHF) {
                        $result.LastUpdateKB   = $lastHF.HotFixID
                        $result.LastUpdateDate = $lastHF.InstalledOn.ToString('yyyy-MM-dd')
                    }
                }
                catch { }
                
                # Pending Reboot Detection (registry checks)
                $result.RebootPending = $false
                $result.RebootReasons = ''
                try {
                    $reasons = @()
                    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'CBS' }
                    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'WU' }
                    $pfro = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -EA SilentlyContinue).PendingFileRenameOperations
                    if ($pfro) { $reasons += 'FileRename' }
                    $actNm = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name 'ComputerName' -EA SilentlyContinue).ComputerName
                    $cmpNm = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Name 'ComputerName' -EA SilentlyContinue).ComputerName
                    if ($actNm -ne $cmpNm) { $reasons += 'Rename' }
                    $result.RebootPending = ($reasons.Count -gt 0)
                    $result.RebootReasons = $reasons -join '; '
                }
                catch { }
                
                # Guest ComputerName (v3.2.0 - Item 22)
                $result.GuestComputerName = $env:COMPUTERNAME
                
                # Guest Network Configuration (v3.2.0 - Item 4 full)
                $result.GuestNetwork = @()
                try {
                    $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }
                    foreach ($adapter in $adapters) {
                        $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
                        $ipv4Addr = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.254.*' }
                        $dnsServers = (Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
                        
                        # Determine DHCP or Static
                        $dhcpEnabled = $false
                        try { $dhcpEnabled = (Get-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp -eq 'Enabled' }
                        catch { }
                        
                        # v3.9.0: DNS suffix collection for cross-domain validation (CR56)
                        $dnsSuffix = ''
                        $dnsSuffixSearchList = ''
                        try {
                            $dnsClient = Get-DnsClient -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
                            if ($dnsClient) {
                                $dnsSuffix = if ($dnsClient.ConnectionSpecificSuffix) { $dnsClient.ConnectionSpecificSuffix } else { '' }
                                $dnsSuffixSearchList = if ($dnsClient.ConnectionSpecificSuffixSearchList) {
                                    ($dnsClient.ConnectionSpecificSuffixSearchList -join '; ')
                                } else { '' }
                            }
                        } catch {}
                        # Also get the global DNS suffix search list (policy-level)
                        $globalSuffixList = ''
                        try {
                            $globalDns = Get-DnsClientGlobalSetting -ErrorAction SilentlyContinue
                            if ($globalDns -and $globalDns.SuffixSearchList) {
                                $globalSuffixList = $globalDns.SuffixSearchList -join '; '
                            }
                        } catch {}

                        foreach ($ip in $ipv4Addr) {
                            $result.GuestNetwork += @{
                                AdapterName   = $adapter.Name
                                IPAddress     = $ip.IPAddress
                                SubnetPrefix  = $ip.PrefixLength
                                SubnetMask    = ([IPAddress]([math]::Pow(2,32) - [math]::Pow(2,(32 - $ip.PrefixLength)))).IPAddressToString
                                Gateway       = if ($ipConfig.IPv4DefaultGateway) { ($ipConfig.IPv4DefaultGateway.NextHop -join '; ') } else { '' }
                                DNSServers    = if ($dnsServers) { $dnsServers -join '; ' } else { '' }
                                DNSSuffix     = $dnsSuffix
                                DNSSuffixSearchList = if ($dnsSuffixSearchList) { $dnsSuffixSearchList } else { $globalSuffixList }
                                DHCPEnabled   = $dhcpEnabled
                                AddressSource = if ($dhcpEnabled) { 'DHCP' } else { 'Static' }
                                MACAddress    = $adapter.MacAddress
                                LinkSpeed     = $adapter.LinkSpeed
                            }
                        }
                    }
                }
                catch { }
                
                # WinRM / CredSSP configuration inside guest (v3.2.9 enhanced)
                $result.WinRM_Status = 'Running'  # If we got here, WinRM is working
                try {
                    $svc = Get-WSManInstance -ResourceURI winrm/config/Service -ErrorAction SilentlyContinue
                    $result.WinRM_AuthKerberos = if ($svc.Auth) { $svc.Auth.Kerberos } else { '' }
                    $result.WinRM_AuthCredSSP  = if ($svc.Auth) { $svc.Auth.CredSSP } else { '' }
                    $result.WinRM_AuthBasic    = if ($svc.Auth) { $svc.Auth.Basic } else { '' }
                    $result.WinRM_AllowUnencrypted = if ($svc) { $svc.AllowUnencrypted } else { '' }
                    
                    $listeners = @(Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate -ErrorAction SilentlyContinue)
                    $result.WinRM_Listeners = ($listeners | ForEach-Object { "$($_.Transport)://*:$($_.Port)" }) -join '; '
                    $result.WinRM_HTTPS = ($listeners | Where-Object { $_.Transport -eq 'HTTPS' }).Count -gt 0
                    
                    # HTTPS cert expiry if present
                    $httpsListener = $listeners | Where-Object { $_.Transport -eq 'HTTPS' } | Select-Object -First 1
                    if ($httpsListener -and $httpsListener.CertificateThumbprint) {
                        try {
                            $cert = Get-ChildItem "Cert:\LocalMachine\My\$($httpsListener.CertificateThumbprint)" -ErrorAction Stop
                            $result.WinRM_HTTPS_CertExp = $cert.NotAfter.ToString('yyyy-MM-dd')
                        }
                        catch { $result.WinRM_HTTPS_CertExp = '' }
                    }
                    
                    # Timeouts
                    $cfg = Get-WSManInstance -ResourceURI winrm/config -ErrorAction SilentlyContinue
                    $result.WinRM_MaxTimeoutMs = if ($cfg) { $cfg.MaxTimeoutms } else { '' }
                    
                    $result.CredSSP_ServerEnabled = if ($svc.Auth) { $svc.Auth.CredSSP } else { 'Unknown' }
                }
                catch { }
                
                # Secure Boot KB + Registry Validation (v3.2.9 - Session 3)
                $result.SB_KBs = @()
                $result.SB_RegistryReady = $false
                $result.SB_AvailableUpdates = ''
                $result.SB_DBXVersion = ''
                try {
                    # Check for Secure Boot related KBs
                    $allHotfixes = Get-HotFix -ErrorAction SilentlyContinue
                    $sbKBs = @('KB5012170','KB5032370','KB5033436','KB5034441')
                    $foundKBs = @()
                    foreach ($kb in $sbKBs) {
                        $match = $allHotfixes | Where-Object { $_.HotFixID -eq $kb }
                        if ($match) {
                            $foundKBs += @{
                                KB = $kb
                                InstalledOn = if ($match.InstalledOn) { $match.InstalledOn.ToString('yyyy-MM-dd') } else { 'Unknown' }
                                Status = 'Installed'
                            }
                        }
                        else {
                            $foundKBs += @{ KB = $kb; InstalledOn = ''; Status = 'NotInstalled' }
                        }
                    }
                    $result.SB_KBs = $foundKBs
                    
                    # Check Secure Boot registry state
                    if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot') {
                        $sbState = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction SilentlyContinue
                        $result.SB_UEFIEnabled = if ($sbState -and $sbState.UEFISecureBootEnabled) { $true } else { $false }
                        
                        $avail = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name 'AvailableUpdates' -ErrorAction SilentlyContinue
                        $result.SB_AvailableUpdates = if ($avail -and $avail.AvailableUpdates) { $avail.AvailableUpdates.ToString() } else { '0' }
                    }
                    
                    # Check DBX (Secure Boot Forbidden Signatures) version
                    try {
                        $dbx = Get-SecureBootUEFI -Name dbx -ErrorAction SilentlyContinue
                        if ($dbx) { $result.SB_DBXVersion = "Present ($(($dbx.Bytes).Count) bytes)" }
                    }
                    catch { $result.SB_DBXVersion = 'Not Available' }
                }
                catch { }
                
                # Network Connection Profile (v3.2.9 - Session 3)
                $result.NetProfiles = @()
                try {
                    $profiles = Get-NetConnectionProfile -ErrorAction SilentlyContinue
                    foreach ($p in $profiles) {
                        $result.NetProfiles += @{
                            InterfaceAlias  = $p.InterfaceAlias
                            NetworkCategory = $p.NetworkCategory.ToString()
                            IPv4Connectivity = $p.IPv4Connectivity.ToString()
                            Name            = $p.Name
                        }
                    }
                }
                catch { }
                
                # Services Inventory (v3.4.1 - filtered at collection time)
                # Only collects services matching $SvcCollectModes to keep Excel row counts manageable.
                $result.Services = @()
                try {
                    $svcs = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue
                    $collectModes   = $using:SvcCollectModes
                    $excludeNames   = $using:SvcExcludeNames
                    foreach ($s in $svcs) {
                        if ($collectModes -notcontains $s.StartMode) { continue }
                        if ($excludeNames -contains $s.Name)         { continue }
                        $result.Services += @{
                            Name        = $s.Name
                            DisplayName = $s.DisplayName
                            Status      = $s.State
                            StartMode   = $s.StartMode
                            StartName   = $s.StartName
                            PathName    = $s.PathName
                            Description = if ($s.Description) { $s.Description.Substring(0, [Math]::Min(200, $s.Description.Length)) } else { '' }
                        }
                    }
                }
                catch { }
                
                # Reboot History from VM guest (v3.2.0 - Item 28)
                # v3.10.9 CR94: Also collect Kernel-Power Event 41 (unexpected reboot) and
                # EventLog Event 6008 (previous unexpected shutdown). These indicate "dirty"
                # reboots where the OS did NOT initiate the shutdown -- it just lost power
                # or crashed. Event 1074 only captures clean/initiated shutdowns.
                $result.RebootHistory = @()
                try {
                    # Clean shutdowns (Event 1074)
                    $evts1074 = Get-EventLog -LogName System -ErrorAction SilentlyContinue |
                        Where-Object { $_.EventId -eq 1074 } |
                        Select-Object -First 10
                    foreach ($evt in $evts1074) {
                        if ($evt.ReplacementStrings[4]) {
                            $result.RebootHistory += @{
                                Date     = $evt.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss')
                                User     = $evt.ReplacementStrings[6]
                                Process  = $evt.ReplacementStrings[0]
                                Action   = $evt.ReplacementStrings[4]
                                Reason   = $evt.ReplacementStrings[2]
                                Computer = $env:COMPUTERNAME
                                RebootType = 'Clean'
                            }
                        }
                    }

                    # Unexpected reboots -- Kernel-Power Event 41 (Critical)
                    # "The system has rebooted without cleanly shutting down first"
                    try {
                        $evts41 = Get-WinEvent -FilterHashtable @{
                            LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41
                        } -MaxEvents 10 -ErrorAction SilentlyContinue
                        foreach ($evt in $evts41) {
                            $result.RebootHistory += @{
                                Date     = $evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                                User     = 'SYSTEM'
                                Process  = 'Kernel-Power'
                                Action   = 'unexpected reboot'
                                Reason   = 'System rebooted without cleanly shutting down first (Kernel-Power 41)'
                                Computer = $env:COMPUTERNAME
                                RebootType = 'Unexpected (Kernel-Power)'
                            }
                        }
                    } catch {}

                    # Previous unexpected shutdown -- EventLog Event 6008 (Error)
                    # "The previous system shutdown at X on Y was unexpected"
                    try {
                        $evts6008 = Get-EventLog -LogName System -ErrorAction SilentlyContinue |
                            Where-Object { $_.EventId -eq 6008 } |
                            Select-Object -First 10
                        foreach ($evt in $evts6008) {
                            $result.RebootHistory += @{
                                Date     = $evt.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss')
                                User     = 'SYSTEM'
                                Process  = 'EventLog'
                                Action   = 'unexpected shutdown detected'
                                Reason   = if ($evt.Message) { ($evt.Message -replace '\r?\n',' ').Substring(0, [math]::Min(200, $evt.Message.Length)) } else { 'Previous unexpected shutdown (EventLog 6008)' }
                                Computer = $env:COMPUTERNAME
                                RebootType = 'Unexpected (EventLog 6008)'
                            }
                        }
                    } catch {}
                }
                catch { }
                
                # Guest Disk Inventory (v3.4.1 - S3-4)
                # Collects local fixed disk usage per drive letter for the VM Guest Storage tab.
                # DriveType 3 = local fixed disk (excludes network, removable, CD/DVD, RAM disk).
                $result.GuestDisks = @()
                try {
                    $drives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop
                    foreach ($d in $drives) {
                        $totalBytes = if ($d.Size)      { [long]$d.Size }      else { 0 }
                        $freeBytes  = if ($d.FreeSpace) { [long]$d.FreeSpace } else { 0 }
                        $usedBytes  = $totalBytes - $freeBytes
                        $totalGB    = [math]::Round($totalBytes / 1GB, 2)
                        $usedGB     = [math]::Round($usedBytes  / 1GB, 2)
                        $freeGB     = [math]::Round($freeBytes  / 1GB, 2)
                        $pctFree    = if ($totalBytes -gt 0) { [math]::Round(($freeBytes / $totalBytes) * 100, 1) } else { 0 }
                        $pctUsed    = if ($totalBytes -gt 0) { [math]::Round(100 - $pctFree, 1) } else { 0 }
                        $result.GuestDisks += @{
                            DriveLetter  = $d.DeviceID       # e.g. "C:"
                            Label        = if ($d.VolumeName) { $d.VolumeName } else { '' }
                            FileSystem   = if ($d.FileSystem) { $d.FileSystem }  else { '' }
                            TotalGB      = $totalGB
                            UsedGB       = $usedGB
                            FreeGB       = $freeGB
                            PercentFree  = $pctFree
                            PercentUsed  = $pctUsed
                            CollectedAt  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                        }
                    }
                }
                catch { }
                
                # Guest Physical Disk SCSI Collection (v3.7.0 - S7)
                # Collects Win32_DiskDrive + WMI join tables to enable VHD-to-drive-letter correlation.
                # SCSILogicalUnit on guest Win32_DiskDrive matches ControllerLocation on the host VHD.
                # Join tables: Win32_DiskDriveToDiskPartition, Win32_LogicalDiskToPartition.
                # This data is processed in the orchestrator's Build-VHDDriveMap function.
                $result.GuestPhysicalDisks  = @()
                $result.GuestDiskToPartition     = @()
                $result.GuestPartitionToLogical  = @()
                try {
                    # Physical disks visible inside the VM -- includes SCSI positioning data
                    $result.GuestPhysicalDisks = @(
                        Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop |
                        ForEach-Object {
                            @{
                                DiskIndex      = [int]$_.Index
                                # SCSI coordinates -- SCSILogicalUnit matches Hyper-V ControllerLocation
                                SCSIBus        = [int]$_.SCSIBus
                                SCSITargetId   = [int]$_.SCSITargetId
                                SCSILogicalUnit = [int]$_.SCSILogicalUnit
                                SCSIPort       = [int]$_.SCSIPort
                                # Size for fallback SizeMatch correlation
                                SizeBytes      = if ($_.Size) { [long]$_.Size } else { 0 }
                                # SerialNumber for Fixed VHD UniqueId correlation
                                SerialNumber   = if ($_.SerialNumber) { $_.SerialNumber.Trim() } else { '' }
                                MediaType      = if ($_.MediaType) { $_.MediaType } else { 'Unknown' }
                                Model          = if ($_.Model) { $_.Model.Trim() } else { '' }
                            }
                        }
                    )
                }
                catch { $result.GuestPhysicalDisks = @() }

                try {
                    # Disk -> Partition join: maps DiskNumber to its partitions
                    # Antecedent.DeviceID = "Disk #1, Partition #0" style string
                    $result.GuestDiskToPartition = @(
                        Get-CimInstance -ClassName Win32_DiskDriveToDiskPartition -ErrorAction Stop |
                        ForEach-Object {
                            $antecedentId = $_.Antecedent.DeviceID   # e.g. "\\.\PHYSICALDRIVE1"
                            $dependentId  = $_.Dependent.DeviceID     # e.g. "Disk #1, Partition #0"
                            $diskNum = -1
                            if ($antecedentId -match 'PHYSICALDRIVE(\d+)') { $diskNum = [int]$Matches[1] }
                            elseif ($dependentId -match 'Disk #(\d+)') { $diskNum = [int]$Matches[1] }
                            @{
                                DiskIndex   = $diskNum
                                PartitionId = $dependentId   # "Disk #N, Partition #M" key for next join
                            }
                        }
                    )
                }
                catch { $result.GuestDiskToPartition = @() }

                try {
                    # Partition -> LogicalDisk join: maps partitions to drive letters
                    # Antecedent.DeviceID = "Disk #1, Partition #0"
                    # Dependent.DeviceID  = "C:" / "D:" etc.
                    $result.GuestPartitionToLogical = @(
                        Get-CimInstance -ClassName Win32_LogicalDiskToPartition -ErrorAction Stop |
                        ForEach-Object {
                            @{
                                PartitionId  = $_.Antecedent.DeviceID   # "Disk #N, Partition #M"
                                DriveLetter  = $_.Dependent.DeviceID    # "C:" "D:" etc.
                            }
                        }
                    )
                }
                catch { $result.GuestPartitionToLogical = @() }

                # Scheduled Tasks Inventory (v3.4.1 - S4b)
                # Collects Enabled/Ready tasks from all non-Microsoft folders by default.
                # $IncludeMicrosoftTasks = $true to include \Microsoft\ folder and subfolders.
                # Uses $using: to reference outer function params inside Invoke-Command.
                $result.ScheduledTasks = @()
                if ($using:IncludeScheduledTasks) {
                    try {
                        $includeMsft = $using:IncludeMicrosoftTasks
                        $includeDisabled = $using:IncludeDisabledTasks
                        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
                            Where-Object {
                                # State filter: always include Ready/Running; Disabled only if param set
                                ($_.State -in @('Ready','Running') -or
                                 ($includeDisabled -and $_.State -eq 'Disabled')) -and
                                # Exclude Microsoft tasks unless explicitly included
                                ($includeMsft -or ($_.TaskPath -notlike '\Microsoft\*' -and $_.TaskPath -ne '\Microsoft'))
                            }
                        foreach ($t in $tasks) {
                            # Build a flat Actions summary string
                            $actionSummary = ($t.Actions | ForEach-Object {
                                if ($_.CimClass.CimClassName -eq 'MSFT_TaskExecAction') {
                                    $args = if ($_.Arguments) { " $($_.Arguments)" } else { '' }
                                    "$($_.Execute)$args"
                                } elseif ($_.CimClass.CimClassName -eq 'MSFT_TaskComHandlerAction') {
                                    "COM: $($_.ClassId)"
                                } else {
                                    $_.CimClass.CimClassName
                                }
                            }) -join ' | '
                            
                            # Get last/next run times safely
                            $lastRun  = try { $t.LastRunTime.ToString('yyyy-MM-dd HH:mm:ss') }  catch { '' }
                            $nextRun  = try { $t.NextRunTime.ToString('yyyy-MM-dd HH:mm:ss') }  catch { '' }
                            $lastCode = try { '0x{0:X8}' -f $t.LastTaskResult } catch { '' }
                            
                            # RunAs account from the principal
                            $runAs = if ($t.Principal.UserId) { $t.Principal.UserId }
                                     elseif ($t.Principal.GroupId) { $t.Principal.GroupId }
                                     else { 'Unknown' }
                            
                            $result.ScheduledTasks += @{
                                TaskName    = $t.TaskName
                                TaskPath    = $t.TaskPath
                                Status      = $t.State.ToString()
                                RunAs       = $runAs
                                LastRunTime = $lastRun
                                NextRunTime = $nextRun
                                LastResult  = $lastCode
                                Description = if ($t.Description) {
                                    $t.Description.Substring(0, [Math]::Min(200, $t.Description.Length)) } else { '' }
                                Actions     = if ($actionSummary) {
                                    $actionSummary.Substring(0, [Math]::Min(300, $actionSummary.Length)) } else { '' }
                            }
                        }
                    }
                    catch { }
                }
                
                # Local Built-in Groups Inventory (v3.8.0 - CR5: expanded from Administrators-only)
                # Collects members of ALL Windows built-in local groups for comprehensive security auditing.
                # Each row includes the GroupName so the Export can show which group the member belongs to.
                # Supports both Get-LocalGroupMember (WS2016+) and ADSI WinNT fallback (WS2012/2008).
                #
                # NOTE on em-dash in AD group names (CR6):
                # AD group names containing the en-dash (U+2013) or em-dash (U+2014) are valid.
                # We collect the Name exactly as returned by the API (Unicode preserved) and store as-is.
                # The Export module comparison uses -like which handles Unicode correctly at runtime.
                # Config-OHDC.psd1 MUST be saved as UTF-8 with BOM so PS 5.1 reads the dash literal.
                $result.LocalBuiltin = @()
                $builtinGroups = @(
                    'Administrators',
                    'Backup Operators',
                    'Remote Desktop Users',
                    'Remote Management Users',
                    'Power Users',
                    'Users',
                    'Guests',
                    'IIS_IUSRS',
                    'Performance Monitor Users',
                    'Performance Log Users',
                    'Distributed COM Users',
                    'Event Log Readers',
                    'Cryptographic Operators',
                    'Hyper-V Administrators',
                    'Access Control Assistance Operators',
                    'Network Configuration Operators'
                )
                foreach ($groupName in $builtinGroups) {
                    try {
                        # Prefer Get-LocalGroupMember (WS2016+) -- preserves Unicode names correctly
                        $members = Get-LocalGroupMember -Group $groupName -ErrorAction Stop
                        foreach ($m in $members) {
                            $result.LocalBuiltin += @{
                                GroupName       = $groupName
                                Name            = $m.Name
                                ObjectClass     = $m.ObjectClass
                                PrincipalSource = if ($m.PrincipalSource) { $m.PrincipalSource.ToString() } else { 'Unknown' }
                            }
                        }
                    }
                    catch [Microsoft.PowerShell.Commands.GroupNotFoundException] {
                        # Group does not exist on this machine -- skip silently
                    }
                    catch {
                        # Fallback: ADSI WinNT provider (WS2012 / WS2008)
                        # ADSI also preserves Unicode name strings correctly
                        try {
                            $adsiGroup = [ADSI]"WinNT://./$groupName,group"
                            foreach ($m in $adsiGroup.psbase.Invoke('Members')) {
                                $mName    = $m.GetType().InvokeMember('Name',    'GetProperty', $null, $m, $null)
                                $mPath    = $m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
                                $mClass   = $m.GetType().InvokeMember('Class',   'GetProperty', $null, $m, $null)
                                $mDomain  = if ($mPath -match 'WinNT://([^/]+)/') { $matches[1] } else { '' }
                                $result.LocalBuiltin += @{
                                    GroupName       = $groupName
                                    Name            = if ($mDomain) { "$mDomain\$mName" } else { $mName }
                                    ObjectClass     = if ($mClass -eq 'Group') { 'Group' } else { 'User' }
                                    PrincipalSource = 'ADSI'
                                }
                            }
                        }
                        catch { }
                    }
                }
                # Backward-compat alias: LocalAdmins still populated from LocalBuiltin Administrators rows
                $result.LocalAdmins = @($result.LocalBuiltin | Where-Object { $_.GroupName -eq 'Administrators' })

                # Roles and Features collection (v3.8.0 - CR4: added InstallState + MachineType columns)
                # Get-WindowsFeature only available on Windows Server (not Desktop SKU).
                # .NET version read from registry on all Windows versions.
                # All rows are INSTALLED features only -- InstallState='Installed' is explicit in every row.
                # MachineType is set at export time (Host vs VM) -- placeholder 'Unknown' here.
                $result.Features = @()
                try {
                    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
                        $installed = Get-WindowsFeature -ErrorAction SilentlyContinue |
                                     Where-Object { $_.InstallState -eq 'Installed' }
                        foreach ($f in $installed) {
                            $result.Features += @{
                                Name        = $f.Name
                                DisplayName = $f.DisplayName
                                FeatureType = $f.FeatureType.ToString()
                                InstallState = 'Installed'
                                MachineType = 'Unknown'   # filled at export time
                                Installed   = $true
                                Source      = 'WindowsFeature'
                            }
                        }
                    }

                    # .NET Framework via registry (all Windows)
                    $v4 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue
                    if ($v4 -and $v4.Release) {
                        $rel = $v4.Release
                        $dotNetVer = switch ($true) {
                            ($rel -ge 533320) { '4.8.1' }
                            ($rel -ge 528040) { '4.8'   }
                            ($rel -ge 461808) { '4.7.2' }
                            ($rel -ge 461308) { '4.7.1' }
                            ($rel -ge 460798) { '4.7'   }
                            ($rel -ge 394802) { '4.6.2' }
                            ($rel -ge 394254) { '4.6.1' }
                            ($rel -ge 393295) { '4.6'   }
                            ($rel -ge 379893) { '4.5.2' }
                            default           { "4.x (rel $rel)" }
                        }
                        $result.Features += @{
                            Name        = 'DotNet-Framework'
                            DisplayName = ".NET Framework $dotNetVer"
                            FeatureType = 'Framework'
                            InstallState = 'Installed'
                            MachineType = 'Unknown'
                            Installed   = $true
                            Source      = 'Registry'
                        }
                    }

                    # .NET Core / .NET 5+
                    $dotnetBin = 'C:\Program Files\dotnet\shared\Microsoft.NETCore.App'
                    if (Test-Path $dotnetBin) {
                        $coreVer = (Get-ChildItem $dotnetBin -Directory -ErrorAction SilentlyContinue |
                            Sort-Object Name -Descending | Select-Object -First 1).Name
                        if ($coreVer) {
                            $result.Features += @{
                                Name        = 'DotNet-Core'
                                DisplayName = ".NET $coreVer (Core/5+)"
                                FeatureType = 'Framework'
                                InstallState = 'Installed'
                                MachineType = 'Unknown'
                                Installed   = $true
                                Source      = 'FileSystem'
                            }
                        }
                    }
                }
                catch { }
            }
            catch {
                # Not Windows, try Linux detection
                try {
                    if (Test-Path "/etc/os-release") {
                        $osRelease = Get-Content "/etc/os-release" -ErrorAction Stop | 
                            ForEach-Object {
                                if ($_ -match '^(.+?)=(.+)$') {
                                    @{$matches[1] = $matches[2] -replace '"',''}
                                }
                            } | ForEach-Object { $_ }
                        
                        $result.OSType = "Linux"
                        $result.OSName = $osRelease.PRETTY_NAME
                        $result.OSVersion = $osRelease.VERSION_ID
                        $result.KernelVersion = & uname -r
                        $result.OSArchitecture = & uname -m
                        
                        # Get last boot time
                        $uptime = Get-Content /proc/uptime -ErrorAction SilentlyContinue
                        if ($uptime) {
                            $uptimeSec = ($uptime -split ' ')[0]
                            $bootTime = (Get-Date).AddSeconds(-[double]$uptimeSec)
                            $result.LastBootTime = $bootTime.ToString("yyyy-MM-dd HH:mm:ss")
                        }
                    }
                }
                catch {
                    $result.OSType = "Unknown"
                    $result.Error = "Could not detect OS type"
                }
            }
            
            $result
        }  # v3.10.5: -Credential and -Authentication are in $icParams above
        
        # Merge results
        foreach ($key in $guestOS.Keys) {
            $osInfo[$key] = $guestOS[$key]
        }
        
        # Get applications if requested
        if ($IncludeApplications -and $osInfo.OSType -ne "Unknown") {
            try {
                Write-Verbose "Collecting applications from $VMName (this may take time)..."
                $osInfo.Applications = Get-InstalledApplications `
                    -ComputerName $VMName `
                    -OSType $osInfo.OSType `
                    -Credential $Credential `
                    -Authentication $Authentication
            }
            catch {
                Write-Verbose "Could not retrieve applications: $($_.Exception.Message)"
            }
        }
    }
    catch {
        # WinRM failed -- try WMI/DCOM fallback for legacy OS (2003/2008)
        Write-Verbose "WinRM failed for $VMName, trying WMI/DCOM fallback: $($_.Exception.Message)"
        
        try {
            $wmiParams = @{ ComputerName = $VMName; ErrorAction = 'Stop' }
            if ($Credential) { $wmiParams['Credential'] = $Credential }
            
            $os = Get-WmiObject -Class Win32_OperatingSystem @wmiParams
            $cs = Get-WmiObject -Class Win32_ComputerSystem @wmiParams
            
            if ($os) {
                $osInfo.OSType = "Windows"
                $osInfo.OSName = $os.Caption
                $osInfo.OSVersion = $os.Version
                $osInfo.OSBuild = $os.BuildNumber
                $osInfo.OSArchitecture = $os.OSArchitecture
                $osInfo.ServicePack = if ($os.ServicePackMajorVersion -gt 0) { "SP$($os.ServicePackMajorVersion)" } else { "N/A" }
                $osInfo.Domain = if ($cs) { $cs.Domain } else { "Unknown" }
                $osInfo.LicenseStatus = "Unknown (WMI)"
                
                try { $osInfo.InstallDate = [Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate).ToString("yyyy-MM-dd") }
                catch { $osInfo.InstallDate = "Unknown" }
                
                try { $osInfo.LastBootTime = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime).ToString("yyyy-MM-dd HH:mm:ss") }
                catch { $osInfo.LastBootTime = "Unknown" }
                
                # WMI fallback: Last update via Win32_QuickFixEngineering
                try {
                    $lastHF = Get-WmiObject -Class Win32_QuickFixEngineering @wmiParams |
                        Where-Object { $_.InstalledOn } |
                        Sort-Object { [DateTime]$_.InstalledOn } -Descending -ErrorAction SilentlyContinue |
                        Select-Object -First 1
                    if ($lastHF) {
                        $osInfo.LastUpdateKB   = $lastHF.HotFixID
                        $osInfo.LastUpdateDate = try { ([DateTime]$lastHF.InstalledOn).ToString('yyyy-MM-dd') } catch { $lastHF.InstalledOn }
                    }
                }
                catch { }
                
                # WMI fallback: Activation method
                try {
                    $lic = Get-WmiObject -Class SoftwareLicensingProduct @wmiParams |
                        Where-Object { $_.PartialProductKey -and $_.Name -like "*Windows*" } |
                        Select-Object -First 1
                    if ($lic) {
                        $osInfo.LicenseStatus = switch ($lic.LicenseStatus) { 0 { "Unlicensed" } 1 { "Licensed" } 5 { "Notification" } default { "Unknown" } }
                        $osInfo.PartialKey = if ($lic.PartialProductKey) { $lic.PartialProductKey } else { '' }
                        $desc = if ($lic.Description) { $lic.Description } else { '' }
                        if ($desc -match 'AVMA') { $osInfo.ActivationMethod = 'AVMA' }
                        elseif ($desc -match 'KMS') { $osInfo.ActivationMethod = 'KMS'; $osInfo.KMSServer = $lic.DiscoveredKeyManagementServiceMachineName }
                        elseif ($desc -match 'MAK') { $osInfo.ActivationMethod = 'MAK' }
                        elseif ($desc -match 'RETAIL') { $osInfo.ActivationMethod = 'Retail' }
                    }
                }
                catch { }
                
                Write-Verbose "WMI/DCOM fallback succeeded for $VMName : $($osInfo.OSName)"
                
                # Try WMI-based app inventory for legacy OS
                if ($IncludeApplications) {
                    try {
                        $apps = Get-WmiObject -Class Win32_Product @wmiParams | 
                            Where-Object { $_.Name } |
                            Select-Object @{N='Name';E={$_.Name}},
                                          @{N='Version';E={$_.Version}},
                                          @{N='Publisher';E={$_.Vendor}},
                                          @{N='InstallDate';E={$_.InstallDate}},
                                          @{N='InstallLocation';E={''}},
                                          @{N='EstimatedSizeMB';E={0}}
                        $osInfo.Applications = @($apps)
                    }
                    catch {
                        Write-Verbose "WMI app inventory failed for $VMName : $($_.Exception.Message)"
                    }
                }
            }
        }
        catch {
            $osInfo.Error = "Cannot connect via WinRM or WMI: $($_.Exception.Message)"
            Write-Verbose $osInfo.Error
        }
    }
    
    return $osInfo
}

function Get-InstalledApplications {
    <#
    .SYNOPSIS
        Gets list of installed applications (Windows or Linux)
        
    .NOTES
        TIME-INTENSIVE! Can take 10-30 seconds per system
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("Windows", "Linux", "Unknown")]
        [string]$OSType,
        
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential,

        # v3.10.5 CR84: Authentication method override
        [Parameter(Mandatory=$false)]
        [string]$Authentication = 'Default'
    )
    
    Write-Verbose "Retrieving installed applications from $ComputerName ($OSType)"
    
    $applications = @()
    
    try {
        if ($OSType -eq "Windows") {
            $appParams = @{ ComputerName = $ComputerName; ErrorAction = 'Stop' }
            if ($Credential) { $appParams['Credential'] = $Credential }
            if ($Authentication -ne 'Default') { $appParams['Authentication'] = $Authentication }
            $applications = Invoke-Command @appParams -ScriptBlock {
                $apps = @()
                
                # Registry paths for installed applications
                $registryPaths = @(
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
                )
                
                foreach ($path in $registryPaths) {
                    try {
                        $apps += Get-ItemProperty $path -ErrorAction SilentlyContinue | 
                            Where-Object { $_.DisplayName } |
                            Select-Object @{N='Name';E={$_.DisplayName}},
                                          @{N='Version';E={$_.DisplayVersion}},
                                          @{N='Publisher';E={$_.Publisher}},
                                          @{N='InstallDate';E={$_.InstallDate}},
                                          @{N='InstallLocation';E={$_.InstallLocation}},
                                          @{N='EstimatedSizeMB';E={
                                              if ($_.EstimatedSize) { 
                                                  [math]::Round($_.EstimatedSize / 1024, 2) 
                                              } else { 
                                                  0 
                                              }
                                          }}
                    }
                    catch {
                        # Continue if one registry path fails
                    }
                }
                
                # Remove duplicates
                $apps | Sort-Object Name -Unique
            }  # v3.10.5: -Credential and -Authentication in $appParams
        }
        elseif ($OSType -eq "Linux") {
            $appParams = @{ ComputerName = $ComputerName; ErrorAction = 'Stop' }
            if ($Credential) { $appParams['Credential'] = $Credential }
            if ($Authentication -ne 'Default') { $appParams['Authentication'] = $Authentication }
            $applications = Invoke-Command @appParams -ScriptBlock {
                $packages = @()
                
                # Try dpkg (Debian/Ubuntu)
                if (Get-Command dpkg -ErrorAction SilentlyContinue) {
                    try {
                        $dpkgList = & dpkg -l | Where-Object { $_ -match '^ii' }
                        foreach ($line in $dpkgList) {
                            $parts = $line -split '\s+'
                            if ($parts.Count -ge 4) {
                                $packages += [PSCustomObject]@{
                                    Name = $parts[1]
                                    Version = $parts[2]
                                    Publisher = "Debian/Ubuntu"
                                    Architecture = $parts[3]
                                }
                            }
                        }
                    }
                    catch {
                        # dpkg failed
                    }
                }
                # Try rpm (RHEL/CentOS)
                elseif (Get-Command rpm -ErrorAction SilentlyContinue) {
                    try {
                        $rpmList = & rpm -qa --queryformat "%{NAME}|%{VERSION}|%{VENDOR}\n"
                        foreach ($line in $rpmList) {
                            $parts = $line -split '\|'
                            if ($parts.Count -ge 2) {
                                $packages += [PSCustomObject]@{
                                    Name = $parts[0]
                                    Version = $parts[1]
                                    Publisher = if ($parts.Count -ge 3) { $parts[2] } else { "Unknown" }
                                }
                            }
                        }
                    }
                    catch {
                        # rpm failed
                    }
                }
                
                $packages
            }  # v3.10.5: -Credential and -Authentication in $appParams
        }
    }
    catch {
        Write-Verbose "Could not retrieve applications from $ComputerName : $($_.Exception.Message)"
    }
    
    return $applications
}

Export-ModuleMember -Function @(
    'Get-VMOperatingSystemInfo',
    'Get-InstalledApplications'
)
