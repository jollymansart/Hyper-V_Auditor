#Requires -Version 5.1
#Requires -Modules FailoverClusters
<#
.SYNOPSIS
    Diagnoses WMI health across all MHOHCLUHV cluster nodes and validates
    cluster role registration integrity.

.DESCRIPTION
    Performs the following checks on each node:
      1. Basic WMI connectivity (root\cimv2)
      2. Hyper-V WMI provider (root\virtualization\v2)
      3. VMMS service state
      4. WinRM responsiveness
      5. Cluster node state
      6. VM inventory vs registered cluster roles (gap detection)
      7. Orphaned cluster groups (group exists, no backing VM)
      8. Available Storage group state

    Outputs a color-coded console report and exports a CSV.
    Run this script BEFORE attempting Add-ClusterVirtualMachineRole to
    identify WMI-broken nodes that will cause "Invalid query" errors.

.PARAMETER ClusterName
    FQDN of the cluster. Defaults to MHOHCLUHV.ohdc.com.

.PARAMETER Nodes
    Override the node list. Defaults to mhoh-hv-p01 through p05.

.PARAMETER ExportPath
    Path for the CSV report. Defaults to \\rictx-script-p2\log\MHOH-Maintenance\

.PARAMETER SkipClusterRoleCheck
    Skip the VM vs cluster role gap analysis (faster for pure WMI triage).

.EXAMPLE
    # Full diagnostic
    .\Test-MHOHClusterWMIHealth.ps1

    # Quick WMI-only check
    .\Test-MHOHClusterWMIHealth.ps1 -SkipClusterRoleCheck

    # Check specific nodes
    .\Test-MHOHClusterWMIHealth.ps1 -Nodes @('mhoh-hv-p01','mhoh-hv-p02')

.NOTES
    Run from RICTX-SCRIPT-P2 as ohdc1\mgeorge-adm
    Stored at: \\rictx-script-p2\Script_Dev\Powershell\Script\Hyper-V\
#>
[CmdletBinding()]
param(
    [string]   $ClusterName       = 'MHOHCLUHV.ohdc.com',
    [string[]] $Nodes             = @('mhoh-hv-p01','mhoh-hv-p02','mhoh-hv-p03','mhoh-hv-p04','mhoh-hv-p05'),
    [string]   $ExportPath        = '\\rictx-script-p2\log\MHOH-Maintenance',
    [switch]   $SkipClusterRoleCheck
)

$ErrorActionPreference = 'SilentlyContinue'

# ============================================================
# HELPERS
# ============================================================
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'OK'      { 'Green'    }
        'WARN'    { 'Yellow'   }
        'ERROR'   { 'Red'      }
        'SECTION' { 'Cyan'     }
        'SKIP'    { 'DarkGray' }
        default   { 'White'    }
    }
    Write-Host "[$ts][$Level] $Message" -ForegroundColor $color
}

function Test-WmiNamespace {
    param([string]$ComputerName, [string]$Namespace, [int]$TimeoutSec = 10)
    try {
        $job = Start-Job -ScriptBlock {
            param($cn, $ns)
            Get-WmiObject -ComputerName $cn -Namespace $ns `
                          -Class '__Namespace' -ErrorAction Stop | Select-Object -First 1
        } -ArgumentList $ComputerName, $Namespace

        $result = Wait-Job $job -Timeout $TimeoutSec | Receive-Job
        Remove-Job $job -Force
        return ($null -ne $result -or $true)   # namespace exists even if empty
    } catch {
        return $false
    }
}

function Test-HyperVWmi {
    param([string]$ComputerName, [int]$TimeoutSec = 15)
    try {
        $job = Start-Job -ScriptBlock {
            param($cn)
            Get-WmiObject -ComputerName $cn `
                          -Namespace 'root\virtualization\v2' `
                          -Class 'Msvm_ComputerSystem' `
                          -Filter "Caption='Hosting Computer System'" `
                          -ErrorAction Stop |
                Select-Object ElementName, EnabledState
        } -ArgumentList $ComputerName

        $result = Wait-Job $job -Timeout $TimeoutSec | Receive-Job
        Remove-Job $job -Force
        return $result
    } catch {
        return $null
    }
}

function Get-ServiceState {
    param([string]$ComputerName, [string]$ServiceName)
    try {
        $svc = Get-Service -ComputerName $ComputerName -Name $ServiceName -ErrorAction Stop
        return $svc.Status.ToString()
    } catch {
        return 'Unreachable'
    }
}

function Test-WinRM {
    param([string]$ComputerName)
    try {
        $result = Test-WSMan -ComputerName $ComputerName -ErrorAction Stop
        return ($null -ne $result)
    } catch {
        return $false
    }
}

# ============================================================
# BANNER
# ============================================================
Write-Log ('=' * 60) 'SECTION'
Write-Log ' MHOH Cluster WMI Health Diagnostic' 'SECTION'
Write-Log (' Cluster : {0}' -f $ClusterName) 'SECTION'
Write-Log (' Nodes   : {0}' -f ($Nodes -join ', ')) 'SECTION'
Write-Log (' Run As  : {0}\{1}' -f $env:USERDOMAIN, $env:USERNAME) 'SECTION'
Write-Log (' Time    : {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) 'SECTION'
Write-Log ('=' * 60) 'SECTION'

# ============================================================
# STEP 1: Cluster node state
# ============================================================
Write-Log ''
Write-Log 'STEP 1: Cluster node states' 'SECTION'

$clusterNodeStates = @{}
try {
    $clusterNodes = Get-ClusterNode -Cluster $ClusterName -ErrorAction Stop
    foreach ($cn in $clusterNodes) {
        $clusterNodeStates[$cn.Name.ToLower()] = $cn.State.ToString()
        $level = if ($cn.State -eq 'Up') { 'OK' } else { 'ERROR' }
        Write-Log ('  {0,-20} Cluster state: {1}' -f $cn.Name, $cn.State) $level
    }
} catch {
    Write-Log ('  Failed to query cluster nodes: {0}' -f $_) 'ERROR'
}

# ============================================================
# STEP 2: Per-node WMI health
# ============================================================
Write-Log ''
Write-Log 'STEP 2: Per-node WMI and service health' 'SECTION'

$nodeResults = @()

foreach ($node in $Nodes) {
    Write-Log ''
    Write-Log ('  --- {0} ---' -f $node.ToUpper()) 'SECTION'

    # Ping
    $ping = Test-Connection -ComputerName $node -Count 1 -Quiet
    Write-Log ('    Ping          : {0}' -f (if ($ping) { 'OK' } else { 'FAILED' })) (if ($ping) { 'OK' } else { 'ERROR' })

    # WinRM
    $winrm = Test-WinRM -ComputerName $node
    Write-Log ('    WinRM         : {0}' -f (if ($winrm) { 'OK' } else { 'FAILED' })) (if ($winrm) { 'OK' } else { 'ERROR' })

    # WMI root\cimv2
    $wmiBasic = $false
    try {
        $os = Get-WmiObject -ComputerName $node -Class Win32_OperatingSystem -ErrorAction Stop
        $wmiBasic = $true
        Write-Log ('    WMI cimv2     : OK ({0})' -f $os.Caption) 'OK'
    } catch {
        Write-Log ('    WMI cimv2     : FAILED - {0}' -f $_.Exception.Message) 'ERROR'
    }

    # WMI root\virtualization\v2
    $wmiHyperV = $false
    $hvResult   = Test-HyperVWmi -ComputerName $node
    if ($hvResult -and $hvResult.ElementName) {
        $wmiHyperV = $true
        Write-Log ('    WMI HyperV    : OK (Host: {0}, State: {1})' -f $hvResult.ElementName, $hvResult.EnabledState) 'OK'
    } else {
        Write-Log '    WMI HyperV    : FAILED - root\virtualization\v2 not responding' 'ERROR'
    }

    # VMMS service
    $vmmsState = Get-ServiceState -ComputerName $node -ServiceName 'vmms'
    $vmmsLevel = if ($vmmsState -eq 'Running') { 'OK' } elseif ($vmmsState -eq 'Unreachable') { 'ERROR' } else { 'WARN' }
    Write-Log ('    VMMS service  : {0}' -f $vmmsState) $vmmsLevel

    # WinMgmt service
    $winmgmtState = Get-ServiceState -ComputerName $node -ServiceName 'winmgmt'
    $winmgmtLevel = if ($winmgmtState -eq 'Running') { 'OK' } elseif ($winmgmtState -eq 'Unreachable') { 'ERROR' } else { 'WARN' }
    Write-Log ('    WinMgmt svc   : {0}' -f $winmgmtState) $winmgmtLevel

    # Cluster state
    $clState = $clusterNodeStates[$node.ToLower()]
    if (-not $clState) { $clState = 'Unknown' }
    $clLevel = if ($clState -eq 'Up') { 'OK' } else { 'WARN' }
    Write-Log ('    Cluster node  : {0}' -f $clState) $clLevel

    # Overall health
    $healthy = $ping -and $winrm -and $wmiBasic -and $wmiHyperV -and ($vmmsState -eq 'Running')
    $overallLevel = if ($healthy) { 'OK' } else { 'ERROR' }
    Write-Log ('    OVERALL       : {0}' -f (if ($healthy) { 'HEALTHY' } else { 'DEGRADED - See above' })) $overallLevel

    # Remediation hint
    if (-not $wmiHyperV -and $ping -and $winrm) {
        Write-Log '    REMEDIATION   : Run: Invoke-Command -ComputerName {0} -ScriptBlock { Restart-Service vmms -Force }' 'WARN'
        Write-Log ('                    If that fails, run WMI re-registration on {0}' -f $node) 'WARN'
    }

    $nodeResults += [PSCustomObject]@{
        Node          = $node
        Ping          = $ping
        WinRM         = $winrm
        WMI_CimV2     = $wmiBasic
        WMI_HyperV    = $wmiHyperV
        VMMS_State    = $vmmsState
        WinMgmt_State = $winmgmtState
        Cluster_State = $clState
        Healthy       = $healthy
        Timestamp     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    }
}

# ============================================================
# STEP 3: Cluster group and VM gap analysis
# ============================================================
$gapResults = @()

if (-not $SkipClusterRoleCheck) {
    Write-Log ''
    Write-Log 'STEP 3: VM vs cluster role gap analysis' 'SECTION'

    # Get registered cluster VM roles
    $registeredGroups = @{}
    try {
        $clResources = Get-ClusterResource -Cluster $ClusterName -ErrorAction Stop |
                         Where-Object { $_.ResourceType -eq 'Virtual Machine' }
        foreach ($r in $clResources) {
            $registeredGroups[$r.OwnerGroup.Name.ToLower()] = [PSCustomObject]@{
                GroupName = $r.OwnerGroup.Name
                State     = $r.OwnerGroup.State.ToString()
                OwnerNode = $r.OwnerGroup.OwnerNode.ToString()
            }
        }
        Write-Log ('  Registered cluster VM roles: {0}' -f $registeredGroups.Count)
    } catch {
        Write-Log ('  Failed to query cluster resources: {0}' -f $_) 'ERROR'
    }

    # Get all VMs from healthy nodes only
    $allVMs = @()
    $healthyNodes = $nodeResults | Where-Object { $_.WMI_HyperV -eq $true }

    foreach ($nr in $healthyNodes) {
        try {
            $vms = Get-VM -ComputerName $nr.Node -ErrorAction Stop
            foreach ($vm in $vms) {
                $allVMs += [PSCustomObject]@{
                    VMName = $vm.Name
                    VMId   = $vm.VMId
                    State  = $vm.State.ToString()
                    Node   = $nr.Node
                }
            }
        } catch {
            Write-Log ('  Could not enumerate VMs on {0}: {1}' -f $nr.Node, $_) 'WARN'
        }
    }

    Write-Log ('  VMs found across healthy nodes: {0}' -f $allVMs.Count)

    # Find unregistered VMs
    Write-Log ''
    Write-Log '  --- Unregistered VMs (in Hyper-V but NOT in cluster) ---' 'SECTION'
    $foundUnregistered = $false
    foreach ($vm in $allVMs) {
        if (-not $registeredGroups.ContainsKey($vm.VMName.ToLower())) {
            Write-Log ('  UNREGISTERED: {0} [{1}] on {2}' -f $vm.VMName, $vm.State, $vm.Node) 'WARN'
            $foundUnregistered = $true
            $gapResults += [PSCustomObject]@{
                Type      = 'Unregistered'
                VMName    = $vm.VMName
                Node      = $vm.Node
                VMState   = $vm.State
                CLGroup   = ''
                CLState   = ''
                CLOwner   = ''
                Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            }
        }
    }
    if (-not $foundUnregistered) {
        Write-Log '  None found - all Hyper-V VMs have cluster roles' 'OK'
    }

    # Find orphaned cluster groups (group exists, no VM)
    Write-Log ''
    Write-Log '  --- Orphaned cluster groups (in cluster but no backing VM) ---' 'SECTION'
    $allVMNamesLower = $allVMs | ForEach-Object { $_.VMName.ToLower() }
    $foundOrphaned = $false
    foreach ($key in $registeredGroups.Keys) {
        $grp = $registeredGroups[$key]
        # Strip SCVMM prefix if present for matching
        $cleanName = $grp.GroupName -replace '^SCVMM\s+', ''
        if ($cleanName.ToLower() -notin $allVMNamesLower -and
            $grp.GroupName.ToLower() -notin $allVMNamesLower) {
            Write-Log ('  ORPHANED GROUP: "{0}" State={1} Owner={2}' -f $grp.GroupName, $grp.State, $grp.OwnerNode) 'WARN'
            $foundOrphaned = $true
            $gapResults += [PSCustomObject]@{
                Type      = 'OrphanedGroup'
                VMName    = ''
                Node      = $grp.OwnerNode
                VMState   = ''
                CLGroup   = $grp.GroupName
                CLState   = $grp.State
                CLOwner   = $grp.OwnerNode
                Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            }
        }
    }
    if (-not $foundOrphaned) {
        Write-Log '  None found - all cluster roles have backing VMs' 'OK'
    }

    # Available Storage check
    Write-Log ''
    Write-Log '  --- Cluster group states ---' 'SECTION'
    try {
        $allGroups = Get-ClusterGroup -Cluster $ClusterName -ErrorAction Stop
        foreach ($grp in ($allGroups | Sort-Object State)) {
            $level = if ($grp.State -eq 'Online') { 'OK' } else { 'WARN' }
            Write-Log ('  {0,-45} {1,-10} Owner: {2}' -f $grp.Name, $grp.State, $grp.OwnerNode) $level
        }
    } catch {
        Write-Log ('  Failed to query cluster groups: {0}' -f $_) 'ERROR'
    }
}

# ============================================================
# STEP 4: Remediation summary
# ============================================================
Write-Log ''
Write-Log ('=' * 60) 'SECTION'
Write-Log ' REMEDIATION SUMMARY' 'SECTION'
Write-Log ('=' * 60) 'SECTION'

$degradedNodes = $nodeResults | Where-Object { $_.Healthy -eq $false }
if ($degradedNodes.Count -eq 0) {
    Write-Log '  All nodes healthy - cluster WMI is fully operational' 'OK'
} else {
    Write-Log ('  {0} degraded node(s) detected:' -f $degradedNodes.Count) 'ERROR'
    foreach ($dn in $degradedNodes) {
        Write-Log ('  Node: {0}' -f $dn.Node) 'ERROR'

        if (-not $dn.Ping) {
            Write-Log '    -> Node is not responding to ping. Check power/network.' 'ERROR'
        } elseif (-not $dn.WinRM) {
            Write-Log '    -> WinRM not responding. Check WinRM service and firewall.' 'WARN'
        } elseif (-not $dn.WMI_HyperV -and $dn.WMI_CimV2) {
            Write-Log ('    -> Hyper-V WMI provider broken. Run on {0}:' -f $dn.Node) 'WARN'
            Write-Log '       Invoke-Command -ComputerName {0} -ScriptBlock {' 'WARN'
            Write-Log '           Stop-Service winmgmt -Force' 'WARN'
            Write-Log ('           Get-ChildItem "$env:SystemRoot\System32\wbem" -Filter "*.dll" |') 'WARN'
            Write-Log '               ForEach-Object { regsvr32.exe /s $_.FullName }' 'WARN'
            Write-Log '           Start-Service winmgmt' 'WARN'
            Write-Log '           Restart-Service vmms -Force' 'WARN'
            Write-Log '       }' 'WARN'
        } elseif (-not $dn.WMI_CimV2) {
            Write-Log ('    -> Base WMI broken. Consider restarting WMI on {0}.' -f $dn.Node) 'WARN'
        }

        if ($dn.VMMS_State -ne 'Running') {
            Write-Log ('    -> VMMS not running. Run: Invoke-Command -ComputerName {0} -ScriptBlock {{ Restart-Service vmms -Force }}' -f $dn.Node) 'WARN'
        }
    }
}

Write-Log ''
Write-Log '  NOTE: Add-ClusterVirtualMachineRole will fail with "Invalid query"' 'WARN'
Write-Log '        if ANY cluster node has broken Hyper-V WMI.' 'WARN'
Write-Log '        Fix ALL degraded nodes before attempting cluster role registration.' 'WARN'

# ============================================================
# EXPORT
# ============================================================
if (-not (Test-Path $ExportPath)) {
    New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
}

$ts         = Get-Date -Format 'yyyyMMdd_HHmmss'
$nodeReport = Join-Path $ExportPath "ClusterWMIHealth_Nodes_$ts.csv"
$gapReport  = Join-Path $ExportPath "ClusterWMIHealth_Gaps_$ts.csv"

$nodeResults | Export-Csv -Path $nodeReport -NoTypeInformation -Encoding UTF8
Write-Log ''
Write-Log ('  Node report : {0}' -f $nodeReport) 'OK'

if ($gapResults.Count -gt 0) {
    $gapResults | Export-Csv -Path $gapReport -NoTypeInformation -Encoding UTF8
    Write-Log ('  Gap report  : {0}' -f $gapReport) 'OK'
}

Write-Log ('=' * 60) 'SECTION'
