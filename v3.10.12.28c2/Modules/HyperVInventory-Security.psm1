<#
.SYNOPSIS
    HyperV Inventory v3.2.9 - Security & Firmware Module
    
.DESCRIPTION
    Functions for analyzing firmware (BIOS/UEFI), Secure Boot, TPM, and certificates.
    
    This module is MIXED-PLATFORM: most functions are OS/security-probing that
    work against any Windows machine (Hyper-V guest, VMware guest, bare metal),
    but Get-VMFirmwareInfo specifically queries Hyper-V firmware settings and
    only runs during the Hyper-V collection phase. For that function, the
    orchestrator guarantees the Hyper-V module is loaded before invoking it.
    Hyper-V cmdlets in this module use the fully-qualified Hyper-V\ prefix
    for cmdlet resolution safety (see Core.psm1 header for the full contract).
    
.NOTES
    Author: Michael George
    Version: 3.10.12-Security
    Date: April 11, 2026
    
    v3.10.10 CR101: Hyper-V\ prefix on Get-VM, Get-VMFirmware, and Get-VMSecurity
                    inside the Get-VMFirmwareInfo remote scriptblock to prevent
                    cmdlet shadowing by VMware PowerCLI / SCVMM.
#>

#Requires -Version 5.0

function Get-VMFirmwareInfo {
    <#
    .SYNOPSIS
        Gets firmware and security information for a VM
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory=$true)]
        [string]$VMName,
        
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential
    )
    
    $invokeParams = @{
        ComputerName = $ComputerName
        ErrorAction = 'Stop'
    }
    if ($Credential) { $invokeParams['Credential'] = $Credential }
    
    try {
        $firmwareInfo = Invoke-Command @invokeParams -ArgumentList $VMName -ScriptBlock {
            param($VMName)
            
            # v3.10.10 CR101: Remote-side module isolation. Import Hyper-V
            # explicitly to prevent Get-VM/Get-VMFirmware/Get-VMSecurity from
            # resolving to VMware PowerCLI, SCVMM, or other shadowing modules
            # if they happen to be installed on this remote Hyper-V host.
            try {
                Import-Module Hyper-V -Force -DisableNameChecking -ErrorAction Stop
            }
            catch {
                return @{
                    Generation = 0; FirmwareType = 'Unknown'
                    SecureBootEnabled = $false; SecureBootTemplate = 'ModuleLoadFailed'
                    TPMEnabled = $false
                    Error = "CR101: Hyper-V module load failed on remote host: $($_.Exception.Message)"
                }
            }
            
            # v3.10.10 CR101: Hyper-V\ prefix for ambiguous cmdlets
            $vm = Hyper-V\Get-VM -Name $VMName
            $result = @{
                Generation = $vm.Generation
                FirmwareType = if ($vm.Generation -eq 1) { "BIOS" } else { "UEFI" }
                SecureBootEnabled = $false
                SecureBootTemplate = "N/A"
                TPMEnabled = $false
            }
            
            # Gen 2 VMs have Secure Boot and TPM options
            if ($vm.Generation -eq 2) {
                try {
                    # v3.10.10 CR101: Hyper-V\ prefix
                    $firmware = Hyper-V\Get-VMFirmware -VMName $VMName -ErrorAction Stop
                    $result.SecureBootEnabled = $firmware.SecureBoot -eq 'On'
                    $result.SecureBootTemplate = $firmware.SecureBootTemplate
                }
                catch {
                    # Firmware cmdlet failed
                }
                
                # Check for TPM
                try {
                    # v3.10.10 CR101: Hyper-V\ prefix
                    $security = Hyper-V\Get-VMSecurity -VMName $VMName -ErrorAction SilentlyContinue
                    if ($security) {
                        $result.TPMEnabled = $security.TpmEnabled
                    }
                }
                catch {
                    # TPM cmdlet not available
                }
            }
            
            $result
        }
        
        return $firmwareInfo
    }
    catch {
        Write-Verbose "Could not retrieve firmware info for $VMName on $ComputerName : $($_.Exception.Message)"
        return @{
            Generation = "Unknown"
            FirmwareType = "Unknown"
            SecureBootEnabled = $false
            SecureBootTemplate = "Error"
            TPMEnabled = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-HostFirmwareInfo {
    <#
    .SYNOPSIS
        Gets firmware and security information for a physical host
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential
    )
    
    $invokeParams = @{
        ComputerName = $ComputerName
        ErrorAction = 'Stop'
    }
    if ($Credential) { $invokeParams['Credential'] = $Credential }
    
    try {
        $hostFirmware = Invoke-Command @invokeParams -ScriptBlock {
            $result = @{
                FirmwareType = "Unknown"
                SecureBootEnabled = $false
                TPMVersion = "Not Available"
                VirtualizationEnabled = "Unknown"
                Manufacturer = ""
                Model = ""
                BIOSVersion = ""
                HostType = "Unknown"
            }
            
            # Get computer system info
            try {
                $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                $result.Manufacturer = $computerSystem.Manufacturer
                $result.Model = $computerSystem.Model
                
                # Detect if physical or virtual
                $isVirtual = $computerSystem.Model -match "Virtual|VMware|Hyper-V|Xen|KVM"
                $result.HostType = if ($isVirtual) { "Virtual" } else { "Physical" }
            }
            catch {
                # Continue even if this fails
            }
            
            # Get BIOS info
            try {
                $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
                $result.BIOSVersion = $bios.SMBIOSBIOSVersion
            }
            catch {
                $result.BIOSVersion = "Unknown"
            }
            
            # Determine firmware type (BIOS vs UEFI)
            try {
                # Check bcdedit for UEFI indicators
                $bcdeditOutput = & bcdedit.exe /enum "{current}" 2>$null
                if ($bcdeditOutput -match "\\EFI\\") {
                    $result.FirmwareType = "UEFI"
                } else {
                    $result.FirmwareType = "BIOS"
                }
            }
            catch {
                # Alternative method - check for EFI variables
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State") {
                    $result.FirmwareType = "UEFI"
                } else {
                    $result.FirmwareType = "BIOS"
                }
            }
            
            # Get Secure Boot status (UEFI only)
            try {
                $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
                $result.SecureBootEnabled = $secureBoot
            }
            catch {
                $result.SecureBootEnabled = $false
            }
            
            # Get TPM info
            try {
                $tpm = Get-Tpm -ErrorAction SilentlyContinue
                if ($tpm -and $tpm.TpmPresent) {
                    try {
                        $tpmWmi = Get-CimInstance -Namespace "root\CIMv2\Security\MicrosoftTpm" `
                            -ClassName Win32_Tpm -ErrorAction SilentlyContinue
                        if ($tpmWmi) {
                            $result.TPMVersion = $tpmWmi.SpecVersion
                        } else {
                            $result.TPMVersion = "Present (Version Unknown)"
                        }
                    }
                    catch {
                        $result.TPMVersion = "Present (Version Unknown)"
                    }
                } else {
                    $result.TPMVersion = "Not Present"
                }
            }
            catch {
                $result.TPMVersion = "Not Available"
            }
            
            # Check virtualization extensions
            try {
                $processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | 
                    Select-Object -First 1
                if ($processor.VirtualizationFirmwareEnabled) {
                    $result.VirtualizationEnabled = "Enabled"
                } else {
                    $result.VirtualizationEnabled = "Disabled"
                }
            }
            catch {
                $result.VirtualizationEnabled = "Unknown"
            }
            
            $result
        }
        
        return $hostFirmware
    }
    catch {
        Write-Verbose "Could not retrieve host firmware info for $ComputerName : $($_.Exception.Message)"
        return @{
            FirmwareType = "Unknown"
            SecureBootEnabled = $false
            TPMVersion = "Error"
            VirtualizationEnabled = "Unknown"
            Manufacturer = "Unknown"
            Model = "Unknown"
            BIOSVersion = "Unknown"
            HostType = "Unknown"
            Error = $_.Exception.Message
        }
    }
}

# v3.9.6: Export-ModuleMember moved to end of file (was here before Invoke-RBACComplianceAudit definition)


function Invoke-RBACComplianceAudit {
    <#
    .SYNOPSIS
        Validates RBAC security group compliance for all servers.

    .DESCRIPTION
        For each server + builtin group combination, computes the expected
        AD security group name (Prefix + HostName + Suffix), then:
          1. Checks if the AD group exists in the target OU
          2. Checks if the AD group is a member of the local builtin group
          3. Checks if the AD group has any members (empty = orphan risk)
          4. Checks if the server computer object exists in AD
          5. Flags cross-domain accounts in local builtin groups

    .PARAMETER HostData
        Array of completed host objects from the main inventory.

    .PARAMETER RBACConfig
        Hashtable from Config-OHDC.psd1 RBACBuiltinGroups section.

    .PARAMETER Credential
        AD query credential.

    .OUTPUTS
        Hashtable with keys:
          RBACCompliance   - [List[PSObject]] per server+group detail rows
          RBACSummary      - [List[PSObject]] per server summary (for Local-Builtin enrichment)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][array]$HostData,
        [Parameter(Mandatory = $true)][hashtable]$RBACConfig,
        [Parameter(Mandatory = $false)][System.Management.Automation.PSCredential]$Credential
    )

    $complianceRows = [System.Collections.Generic.List[object]]::new()
    $summaryRows    = [System.Collections.Generic.List[object]]::new()

    # Extract config
    $prefix    = if ($RBACConfig.ADGroupPrefix) { $RBACConfig.ADGroupPrefix } else { 'ACL_' }
    $ouPath    = if ($RBACConfig.ADGroupOU) { $RBACConfig.ADGroupOU } else { '' }
    $suffixMap = if ($RBACConfig.SuffixMap) { $RBACConfig.SuffixMap } else { @{} }

    if ($suffixMap.Count -eq 0) {
        Write-Warning "RBAC SuffixMap is empty -- skipping RBAC compliance audit."
        return @{ RBACCompliance = $complianceRows; RBACSummary = $summaryRows }
    }

    # ── Cache: AD group existence + membership ────────────────────────
    # Query AD once for all groups in the target OU to avoid per-group lookups.
    $adGroupCache = @{}    # key = group sAMAccountName (lowercase), value = hashtable {Exists, MemberCount, DN}
    $adComputerCache = @{} # key = computer name (lowercase), value = $true/$false

    try {
        $adParams = @{ ErrorAction = 'Stop' }
        if ($Credential) { $adParams['Credential'] = $Credential }

        # Get all groups in the RBAC OU
        if ($ouPath) {
            $adGroups = Get-ADGroup -SearchBase $ouPath -Filter "Name -like '$($prefix)*'" -Properties Members @adParams
            foreach ($grp in $adGroups) {
                $adGroupCache[$grp.SamAccountName.ToLower()] = @{
                    Exists      = $true
                    MemberCount = @($grp.Members).Count
                    DN          = $grp.DistinguishedName
                    Members     = @($grp.Members)
                }
            }
            Write-Verbose "RBAC: Cached $($adGroupCache.Count) AD groups from $ouPath"
        }
    }
    catch {
        Write-Warning "RBAC AD group query failed: $($_.Exception.Message). Will check groups individually."
    }

    # ── Helper: check single AD group ─────────────────────────────────
    function Test-ADGroupExists {
        param([string]$GroupName)

        $key = $GroupName.ToLower()
        if ($adGroupCache.ContainsKey($key)) {
            return $adGroupCache[$key]
        }

        # Individual lookup (cache miss -- group may be outside target OU)
        try {
            $adParams2 = @{ ErrorAction = 'Stop' }
            if ($Credential) { $adParams2['Credential'] = $Credential }
            $grp = Get-ADGroup -Identity $GroupName -Properties Members @adParams2
            $info = @{
                Exists      = $true
                MemberCount = @($grp.Members).Count
                DN          = $grp.DistinguishedName
                Members     = @($grp.Members)
            }
            $adGroupCache[$key] = $info
            return $info
        }
        catch {
            $info = @{ Exists = $false; MemberCount = 0; DN = ''; Members = @() }
            $adGroupCache[$key] = $info
            return $info
        }
    }

    # ── Helper: check computer object exists in AD ────────────────────
    function Test-ADComputerExists {
        param([string]$ComputerName)

        $key = $ComputerName.ToLower()
        if ($adComputerCache.ContainsKey($key)) {
            return $adComputerCache[$key]
        }

        try {
            $adParams3 = @{ ErrorAction = 'Stop' }
            if ($Credential) { $adParams3['Credential'] = $Credential }
            $null = Get-ADComputer -Identity $ComputerName @adParams3
            $adComputerCache[$key] = $true
            return $true
        }
        catch {
            $adComputerCache[$key] = $false
            return $false
        }
    }

    # ── Helper: detect cross-domain account ───────────────────────────
    function Test-CrossDomain {
        param(
            [string]$MemberName,
            [string]$MachineDomain
        )

        if ($MemberName -match '^([^\\]+)\\') {
            $memberDomain = $Matches[1].ToLower()
            $machineDomainShort = ($MachineDomain -split '\.')[0].ToLower()
            # Cross-domain if the prefix doesn't match the machine's domain
            if ($memberDomain -ne $machineDomainShort -and
                $memberDomain -ne $MachineDomain.ToLower()) {
                return $true
            }
        }
        return $false
    }

    # ══════════════════════════════════════════════════════════════════
    # MAIN: Iterate all machines (hosts + VMs)
    # ══════════════════════════════════════════════════════════════════

    # Build a flat list of all machines with their builtin group data
    $allMachines = [System.Collections.Generic.List[object]]::new()

    foreach ($hostObj in $HostData) {
        if ($hostObj.Error) { continue }

        $hostName = $hostObj.HostName
        $hostDomain = ''
        if ($hostObj.HostInfo -and $hostObj.HostInfo.Domain) {
            $hostDomain = $hostObj.HostInfo.Domain
        }
        elseif ($hostObj.Domain) { $hostDomain = $hostObj.Domain }

        # Host itself
        $hostBuiltin = @()
        if ($hostObj.LocalBuiltin) { $hostBuiltin = @($hostObj.LocalBuiltin) }
        elseif ($hostObj.LocalAdmins) {
            $hostBuiltin = @($hostObj.LocalAdmins | ForEach-Object {
                $_ | Add-Member -NotePropertyName 'GroupName' -NotePropertyValue 'Administrators' -Force -PassThru
            })
        }

        $allMachines.Add(@{
            MachineName  = $hostName
            MachineType  = 'Host'
            Domain       = $hostDomain
            ClusterName  = if ($hostObj.ClusterName) { $hostObj.ClusterName } else { '' }
            BuiltinData  = $hostBuiltin
        })

        # VMs on this host
        if ($hostObj.VMs) {
            foreach ($vm in $hostObj.VMs) {
                $vmDisplayName = if ($vm.VM) { $vm.VM } elseif ($vm.VMName) { $vm.VMName } else { continue }

                # v3.10.0: Use guest OS computer name, not Hyper-V display name
                # Same logic as DNS-Validation CR66 -- AD groups use the guest name
                $vmGuestName = ''
                if ($vm.GuestComputerName -and $vm.GuestComputerName.Trim()) {
                    $vmGuestName = $vm.GuestComputerName.Trim()
                }
                elseif ($vm.KVP -and $vm.KVP['FullyQualifiedDomainName'] -and $vm.KVP['FullyQualifiedDomainName'] -match '^([^\.]+)') {
                    $vmGuestName = $Matches[1]
                }

                # v3.10.0: Determine OS type for filtering
                $vmOSType = 'Unknown'
                if ($vm.OSInfo -and $vm.OSInfo.OSType) { $vmOSType = $vm.OSInfo.OSType }
                elseif ($vm.GuestOS) {
                    $gos = $vm.GuestOS.ToString()
                    if ($gos -match '(?i)windows') { $vmOSType = 'Windows' }
                    elseif ($gos -match '(?i)ubuntu|oracle|red\s*hat|sles|centos|debian|linux') { $vmOSType = 'Linux' }
                }
                # Check for appliance pattern (non-domain devices)
                $isAppliance = $vmDisplayName -match '(?i)APPLIANCE|^IPAM|SCG-|CONNEX|FORTI|PFSENSE|OPNSENSE|TRUENAS'

                # Skip appliances entirely -- RBAC rules don't apply
                if ($isAppliance) { continue }

                # For Linux VMs without WinRM access, add a note row but don't check AD groups
                if ($vmOSType -eq 'Linux' -and -not $vm.LocalBuiltin -and -not $vm.LocalAdmins) {
                    $complianceRows.Add([PSCustomObject]@{
                        MachineName       = if ($vmGuestName) { $vmGuestName } else { $vmDisplayName }
                        MachineType       = 'VM (Linux)'
                        ParentHost        = $hostName
                        ClusterName       = if ($hostObj.ClusterName) { $hostObj.ClusterName } else { '' }
                        Domain            = ''
                        ComputerInAD      = 'N/A'
                        BuiltinGroup      = '(all)'
                        ExpectedADGroup   = 'N/A'
                        ADGroupExists     = 'N/A'
                        ADGroupMemberCount = 0
                        ADGroupEmpty      = 'N/A'
                        InLocalBuiltin    = 'N/A'
                        CrossDomainCount  = 0
                        CrossDomainAccounts = ''
                        Status            = 'LINUX'
                        Issues            = 'Need to access Linux OS -- RBAC builtin group validation requires SSH or WinRM access to verify local group membership.'
                    })
                    continue
                }

                # Use guest name for RBAC, fall back to display name
                $vmName = if ($vmGuestName) { $vmGuestName } else { $vmDisplayName }

                $vmDomain = ''
                if ($vm.OSInfo -and $vm.OSInfo.Domain) { $vmDomain = $vm.OSInfo.Domain }

                $vmBuiltin = @()
                if ($vm.LocalBuiltin) { $vmBuiltin = @($vm.LocalBuiltin) }
                elseif ($vm.LocalAdmins) {
                    $vmBuiltin = @($vm.LocalAdmins | ForEach-Object {
                        $_ | Add-Member -NotePropertyName 'GroupName' -NotePropertyValue 'Administrators' -Force -PassThru
                    })
                }

                # Skip VMs with Unknown OS type and no guest name (can't validate)
                if ($vmOSType -eq 'Unknown' -and -not $vmGuestName -and -not $vm.LocalBuiltin) { continue }

                $allMachines.Add(@{
                    MachineName  = $vmName
                    MachineType  = 'VM'
                    Domain       = $vmDomain
                    ClusterName  = if ($hostObj.ClusterName) { $hostObj.ClusterName } else { '' }
                    ParentHost   = $hostName
                    BuiltinData  = $vmBuiltin
                })
            }
        }
    }

    Write-Verbose "RBAC: Auditing $($allMachines.Count) machines against $($suffixMap.Count) builtin groups"

    foreach ($machine in $allMachines) {
        $machineName = $machine.MachineName
        $machineType = $machine.MachineType
        $domain      = $machine.Domain
        $parentHost  = if ($machine.ParentHost) { $machine.ParentHost } else { '' }
        $cluster     = $machine.ClusterName

        # Check computer object exists
        $computerExists = Test-ADComputerExists -ComputerName $machineName

        # Per-group tracking for summary
        $machineGroupsOK      = 0
        $machineGroupsMissing = 0
        $machineGroupsNoAD    = 0
        $machineGroupsEmpty   = 0
        $machineCrossDomain   = 0

        # Get unique builtin group names found on this machine
        $builtinGroupsOnMachine = @($machine.BuiltinData | ForEach-Object { $_.GroupName } | Select-Object -Unique)

        foreach ($builtinGroupName in $suffixMap.Keys) {
            $suffix = $suffixMap[$builtinGroupName]
            $expectedADGroup = "${prefix}${machineName}_${suffix}"

            # Check AD group existence
            $adInfo = Test-ADGroupExists -GroupName $expectedADGroup
            $adExists = $adInfo.Exists
            $adMemberCount = $adInfo.MemberCount
            $adEmpty = ($adExists -and $adMemberCount -eq 0)

            # Check if the AD group is a member of the local builtin group
            $localMembership = $false
            $localMembers = @($machine.BuiltinData | Where-Object { $_.GroupName -eq $builtinGroupName })
            foreach ($m in $localMembers) {
                if ($m.Name -like "*$expectedADGroup*" -or $m.Name -eq $expectedADGroup -or
                    $m.Name -like "*\$expectedADGroup") {
                    $localMembership = $true
                    break
                }
            }

            # Detect cross-domain accounts in this builtin group
            $crossDomainMembers = [System.Collections.Generic.List[string]]::new()
            foreach ($m in $localMembers) {
                if (Test-CrossDomain -MemberName $m.Name -MachineDomain $domain) {
                    $crossDomainMembers.Add($m.Name)
                    $machineCrossDomain++
                }
            }

            # Determine compliance status
            $status = 'COMPLIANT'
            $issues = [System.Collections.Generic.List[string]]::new()

            if (-not $computerExists) {
                $issues.Add('Computer object not found in AD')
            }
            if (-not $adExists) {
                $status = 'NON-COMPLIANT'
                $issues.Add("AD group '$expectedADGroup' does not exist")
                $machineGroupsNoAD++
            }
            else {
                if (-not $localMembership) {
                    $status = 'NON-COMPLIANT'
                    $issues.Add("AD group exists but is not a member of local '$builtinGroupName'")
                    $machineGroupsMissing++
                }
                else {
                    $machineGroupsOK++
                }

                if ($adEmpty) {
                    if ($status -eq 'COMPLIANT') { $status = 'WARNING' }
                    $issues.Add('AD group has no members (empty group)')
                    $machineGroupsEmpty++
                }
            }

            if ($crossDomainMembers.Count -gt 0) {
                if ($status -eq 'COMPLIANT') { $status = 'WARNING' }
                $issues.Add("Cross-domain accounts: $($crossDomainMembers -join '; ')")
            }

            $complianceRows.Add([PSCustomObject]@{
                MachineName       = $machineName
                MachineType       = $machineType
                ParentHost        = $parentHost
                ClusterName       = $cluster
                Domain            = $domain
                ComputerInAD      = if ($computerExists) { 'Yes' } else { 'No' }
                BuiltinGroup      = $builtinGroupName
                ExpectedADGroup   = $expectedADGroup
                ADGroupExists     = if ($adExists) { 'Yes' } else { 'No' }
                ADGroupMemberCount = $adMemberCount
                ADGroupEmpty      = if ($adEmpty) { 'Yes' } else { 'No' }
                InLocalBuiltin    = if ($localMembership) { 'Yes' } else { 'No' }
                CrossDomainCount  = $crossDomainMembers.Count
                CrossDomainAccounts = if ($crossDomainMembers.Count -gt 0) { $crossDomainMembers -join '; ' } else { '' }
                Status            = $status
                Issues            = if ($issues.Count -gt 0) { $issues -join '; ' } else { 'None' }
            })
        }

        # Summary row for this machine
        $overallStatus = if ($machineGroupsNoAD -gt 0 -or $machineGroupsMissing -gt 0) { 'NON-COMPLIANT' }
                         elseif ($machineGroupsEmpty -gt 0 -or $machineCrossDomain -gt 0) { 'WARNING' }
                         else { 'COMPLIANT' }

        $summaryRows.Add([PSCustomObject]@{
            MachineName       = $machineName
            MachineType       = $machineType
            ParentHost        = $parentHost
            Domain            = $domain
            ComputerInAD      = if ($computerExists) { 'Yes' } else { 'No' }
            TotalGroups       = $suffixMap.Count
            GroupsOK          = $machineGroupsOK
            GroupsMissingLocal = $machineGroupsMissing
            GroupsNoAD        = $machineGroupsNoAD
            GroupsEmpty       = $machineGroupsEmpty
            CrossDomainCount  = $machineCrossDomain
            RBACStatus        = $overallStatus
        })
    }

    Write-Verbose "RBAC Audit complete: $($complianceRows.Count) checks, $($summaryRows.Count) machines"

    return @{
        RBACCompliance = $complianceRows
        RBACSummary    = $summaryRows
    }
}

# v3.9.6: Moved to end of file so all functions are defined before export
Export-ModuleMember -Function @(
    'Get-VMFirmwareInfo',
    'Get-HostFirmwareInfo',
    'Invoke-RBACComplianceAudit'
)
