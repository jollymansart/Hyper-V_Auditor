#Requires -Version 5.1
<#
.SYNOPSIS
    Diagnoses WMI health across Hyper-V hosts (standalone or clustered) and
    validates cluster role registration integrity where applicable.

.DESCRIPTION
    Works against standalone Hyper-V hosts AND failover clusters.
    When -ClusterName is provided, cluster-specific checks run (role gaps,
    orphaned groups, CSV health). When omitted, only node-level WMI/service
    checks run - safe for standalone hosts.

    Per-node checks:
      1. Ping
      2. WinRM responsiveness
      3. WMI root\cimv2
      4. WMI root\virtualization\v2 (Hyper-V provider)
      5. VMMS service state
      6. WinMgmt service state
      7. Cluster membership (auto-detected)

    Cluster-only checks (when node is confirmed cluster member):
      8. VM inventory vs registered cluster roles (gap detection)
      9. Orphaned cluster groups (group exists, no backing VM found)
     10. Available Storage group state
     11. CSV health

    Remediation output:
      - Generic description of issue
      - Exact copy-pasteable PowerShell command(s) for each finding
      - Cluster commands only shown when host is confirmed cluster member

.PARAMETER Nodes
    One or more Hyper-V host names to audit. Can be standalone or cluster nodes.

.PARAMETER ClusterName
    Optional. FQDN or short name of the failover cluster.
    If omitted, cluster-specific checks are skipped entirely.
    If provided but a node is not a member, cluster commands are suppressed for that node.

.PARAMETER ExportPath
    Directory for CSV export. Defaults to \\rictx-script-p2\log\MHOH-Maintenance\

.PARAMETER SkipClusterRoleCheck
    Skip VM vs cluster role gap analysis. Useful for quick WMI-only triage.

.PARAMETER WmiTimeoutSec
    Seconds to wait for WMI queries per node. Default 15.

.EXAMPLE
    # Audit all 5 MHOH cluster nodes with full cluster checks
    .\Test-HyperVWMIHealth.ps1 -Nodes mhoh-hv-p01,mhoh-hv-p02,mhoh-hv-p03,mhoh-hv-p04,mhoh-hv-p05 -ClusterName MHOHCLUHV.ohdc.com

    # Audit a standalone host - no cluster commands generated
    .\Test-HyperVWMIHealth.ps1 -Nodes rictx-hv-p01

    # Quick WMI check only, no role gap analysis
    .\Test-HyperVWMIHealth.ps1 -Nodes mhoh-hv-p01,mhoh-hv-p02 -ClusterName MHOHCLUHV.ohdc.com -SkipClusterRoleCheck

    # Mixed - some cluster nodes, some standalone
    .\Test-HyperVWMIHealth.ps1 -Nodes mhoh-hv-p01,mhoh-hv-p02,rictx-hv-standalone -ClusterName MHOHCLUHV.ohdc.com

.NOTES
    Run from RICTX-SCRIPT-P2 as ohdc1\mgeorge-adm
    Stored at: \\rictx-script-p2\Script_Dev\Powershell\Script\Hyper-V\
    PS 5.1 compatible. Plain ASCII only.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]] $Nodes,

    [string]   $ClusterName      = '',
    [string]   $ExportPath       = '\\rictx-script-p2\log\MHOH-Maintenance',
    [switch]   $SkipClusterRoleCheck,
    [int]      $WmiTimeoutSec    = 15
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
        'CMD'     { 'Magenta'  }
        'SKIP'    { 'DarkGray' }
        default   { 'White'    }
    }
    Write-Host "[$ts][$Level] $Message" -ForegroundColor $color
}

function Write-Cmd {
    param([string]$Label, [string]$Command)
    Write-Host "             $Label" -ForegroundColor Yellow
    Write-Host "             >> $Command" -ForegroundColor Magenta
}

function Get-WmiSafe {
    param([string]$ComputerName, [string]$Namespace, [string]$Class, [string]$Filter = '', [int]$TimeoutSec = 15)
    try {
        $job = Start-Job -ScriptBlock {
            param($cn, $ns, $cl, $fi)
            $params = @{
                ComputerName = $cn
                Namespace    = $ns
                Class        = $cl
                ErrorAction  = 'Stop'
            }
            if ($fi) { $params['Filter'] = $fi }
            Get-WmiObject @params
        } -ArgumentList $ComputerName, $Namespace, $Class, $Filter

        $result = Wait-Job $job -Timeout $TimeoutSec | Receive-Job
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        return $result
    } catch {
        return $null
    }
}

function Get-SvcState {
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
        $r = Test-WSMan -ComputerName $ComputerName -ErrorAction Stop
        return ($null -ne $r)
    } catch {
        return $false
    }
}

function Get-ClusterMembership {
    # Returns cluster name if node is a member, empty string if standalone
    param([string]$ComputerName)
    try {
        $cluster = Get-WmiObject -ComputerName $ComputerName `
                       -Namespace 'root\MSCluster' `
                       -Class 'MSCluster_Cluster' `
                       -ErrorAction Stop |
                   Select-Object -First 1
        if ($cluster) { return $cluster.Name } else { return '' }
    } catch {
        return ''
    }
}

# ============================================================
# BANNER
# ============================================================
Write-Log ('=' * 70) 'SECTION'
Write-Log ' Hyper-V WMI Health Diagnostic' 'SECTION'
Write-Log (' Nodes   : {0}' -f ($Nodes -join ', ')) 'SECTION'
Write-Log (' Cluster : {0}' -f (if ($ClusterName) { $ClusterName } else { 'Not specified (standalone mode)' })) 'SECTION'
Write-Log (' Run As  : {0}\{1}' -f $env:USERDOMAIN, $env:USERNAME) 'SECTION'
Write-Log (' Time    : {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) 'SECTION'
Write-Log ('=' * 70) 'SECTION'

# ============================================================
# STEP 1: Cluster node states (only if cluster specified)
# ============================================================
$clNodeStates    = @{}
$clNodeMembers   = @{}   # node.toLower() -> $true if confirmed cluster member

if ($ClusterName) {
    Write-Log ''
    Write-Log 'STEP 1: Cluster node states' 'SECTION'
    try {
        $clNodes = Get-ClusterNode -Cluster $ClusterName -ErrorAction Stop
        foreach ($cn in $clNodes) {
            $key = $cn.Name.ToLower()
            $clNodeStates[$key]  = $cn.State.ToString()
            $clNodeMembers[$key] = $true
            $level = if ($cn.State -eq 'Up') { 'OK' } else { 'ERROR' }
            Write-Log ('  {0,-20} Cluster state: {1}' -f $cn.Name, $cn.State) $level
        }
    } catch {
        Write-Log ('  Failed to query cluster - check connectivity: {0}' -f $_) 'ERROR'
    }
} else {
    Write-Log ''
    Write-Log 'STEP 1: Cluster check skipped - no ClusterName specified (standalone mode)' 'SKIP'
}

# ============================================================
# STEP 2: Per-node WMI and service health
# ============================================================
Write-Log ''
Write-Log 'STEP 2: Per-node WMI and service health' 'SECTION'

$nodeResults = @()

foreach ($node in $Nodes) {
    Write-Log ''
    Write-Log ('  --- {0} ---' -f $node.ToUpper()) 'SECTION'

    # --- Ping ---
    $ping = Test-Connection -ComputerName $node -Count 1 -Quiet -ErrorAction SilentlyContinue
    Write-Log ('    Ping          : {0}' -f (if ($ping) { 'OK' } else { 'FAILED' })) (if ($ping) { 'OK' } else { 'ERROR' })
    if (-not $ping) {
        Write-Log '    Remediation   : Node not responding to ping. Verify power, NIC, and network path.' 'WARN'
        Write-Cmd 'Test network path:' ('Test-NetConnection -ComputerName {0} -Port 5985' -f $node)
        $nodeResults += [PSCustomObject]@{
            Node                = $node
            Ping                = 'FAIL'
            WinRM               = 'N/A'
            WMI_Basic           = 'N/A'
            WMI_HyperV          = 'N/A'
            VMMS                = 'N/A'
            WinMgmt             = 'N/A'
            ClusterMember       = 'N/A'
            ClusterState        = 'N/A'
            OS                  = 'N/A'
            Healthy             = 'NO'
            Issue               = 'Node unreachable (ping failed)'
            Remediation_Generic = 'Verify power, NIC, and network path to node'
            Remediation_Command = ('Test-NetConnection -ComputerName {0} -Port 5985' -f $node)
            Timestamp           = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        }
        continue
    }

    # --- WinRM ---
    $winrm = Test-WinRM -ComputerName $node
    Write-Log ('    WinRM         : {0}' -f (if ($winrm) { 'OK' } else { 'FAILED - WinRM not responding' })) (if ($winrm) { 'OK' } else { 'ERROR' })
    if (-not $winrm) {
        Write-Log '    Remediation   : WinRM not configured or blocked. Enable PSRemoting on the node.' 'WARN'
        Write-Cmd 'Enable WinRM (run locally on node or via console):' ('Invoke-Command -ComputerName {0} -ScriptBlock {{ Enable-PSRemoting -Force; Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force }}' -f $node)
        Write-Cmd 'If WinRM service is stopped:' ('sc.exe \\{0} start WinRM' -f $node)
    }

    # --- WMI root\cimv2 ---
    $wmiBasic  = $false
    $osCaption = ''
    try {
        $os = Get-WmiObject -ComputerName $node -Class Win32_OperatingSystem -ErrorAction Stop
        $wmiBasic  = $true
        $osCaption = $os.Caption
        Write-Log ('    WMI cimv2     : OK ({0})' -f $osCaption) 'OK'
    } catch {
        Write-Log ('    WMI cimv2     : FAILED - {0}' -f $_.Exception.Message) 'ERROR'
        Write-Log '    Remediation   : Base WMI broken. Restart WMI service on node.' 'WARN'
        Write-Cmd 'Restart WMI:' ('Invoke-Command -ComputerName {0} -ScriptBlock {{ net stop winmgmt /y; net start winmgmt }}' -f $node)
    }

    # --- WMI root\virtualization\v2 ---
    $wmiHyperV   = $false
    $hvHostState = ''
    $hvHost = Get-WmiSafe -ComputerName $node `
                  -Namespace 'root\virtualization\v2' `
                  -Class 'Msvm_ComputerSystem' `
                  -Filter "Caption='Hosting Computer System'" `
                  -TimeoutSec $WmiTimeoutSec
    if ($hvHost -and $hvHost.ElementName) {
        $wmiHyperV   = $true
        $hvHostState = $hvHost.EnabledState.ToString()
        Write-Log ('    WMI HyperV    : OK (Host: {0}, State: {1})' -f $hvHost.ElementName, $hvHostState) 'OK'
    } else {
        Write-Log '    WMI HyperV    : FAILED - root\virtualization\v2 not responding' 'ERROR'
        Write-Log '    Remediation   : Hyper-V WMI provider broken. Restart VMMS first, then re-register WMI if needed.' 'WARN'
        Write-Cmd 'Step 1 - Restart VMMS:' ('Invoke-Command -ComputerName {0} -ScriptBlock {{ Restart-Service vmms -Force }}' -f $node)
        Write-Cmd 'Step 2 - If still broken, re-register WMI DLLs:' ('Invoke-Command -ComputerName {0} -ScriptBlock {{ Stop-Service winmgmt -Force; Get-ChildItem "$env:SystemRoot\System32\wbem" -Filter "*.dll" | ForEach-Object {{ regsvr32.exe /s $_.FullName }}; Start-Service winmgmt; Restart-Service vmms -Force }}' -f $node)
    }

    # --- VMMS service ---
    $vmmsState = Get-SvcState -ComputerName $node -ServiceName 'vmms'
    $vmmsLevel = switch ($vmmsState) {
        'Running'     { 'OK'    }
        'Stopped'     { 'ERROR' }
        'Unreachable' { 'ERROR' }
        default       { 'WARN'  }
    }
    Write-Log ('    VMMS service  : {0}' -f $vmmsState) $vmmsLevel
    if ($vmmsState -eq 'Stopped') {
        Write-Cmd 'Start VMMS:' ('Invoke-Command -ComputerName {0} -ScriptBlock {{ Start-Service vmms }}' -f $node)
    } elseif ($vmmsState -notin @('Running','Unreachable')) {
        # Stuck state - StopPending, StartPending, etc.
        Write-Log ('    Remediation   : VMMS is in stuck state ({0}). Force kill and restart.' -f $vmmsState) 'WARN'
        Write-Cmd 'Force kill and restart VMMS:' ('Invoke-Command -ComputerName {0} -ScriptBlock {{ $proc = Get-Process -Name vmms -ErrorAction SilentlyContinue; if ($proc) {{ Stop-Process -Id $proc.Id -Force }}; Start-Sleep -Seconds 3; Start-Service vmms }}' -f $node)
    }

    # --- WinMgmt service ---
    $winmgmtState = Get-SvcState -ComputerName $node -ServiceName 'winmgmt'
    $winmgmtLevel = switch ($winmgmtState) {
        'Running'     { 'OK'    }
        'Stopped'     { 'ERROR' }
        'Unreachable' { 'ERROR' }
        default       { 'WARN'  }
    }
    Write-Log ('    WinMgmt svc   : {0}' -f $winmgmtState) $winmgmtLevel
    if ($winmgmtState -eq 'Stopped') {
        Write-Cmd 'Start WinMgmt:' ('Invoke-Command -ComputerName {0} -ScriptBlock {{ Start-Service winmgmt }}' -f $node)
    } elseif ($winmgmtState -notin @('Running','Unreachable')) {
        Write-Cmd 'Force restart WinMgmt:' ('Invoke-Command -ComputerName {0} -ScriptBlock {{ net stop winmgmt /y; net start winmgmt }}' -f $node)
    }

    # --- Cluster membership (auto-detect) ---
    $detectedCluster = ''
    $isClusterMember = $false

    if ($clNodeMembers.ContainsKey($node.ToLower())) {
        # Already confirmed via Get-ClusterNode above
        $isClusterMember = $true
        $detectedCluster = $ClusterName
    } else {
        # Auto-detect via WMI MSCluster namespace
        if ($wmiBasic) {
            $detectedCluster = Get-ClusterMembership -ComputerName $node
            $isClusterMember = ($detectedCluster -ne '')
        }
    }

    $clState = 'Standalone'
    if ($isClusterMember) {
        $clState = if ($clNodeStates.ContainsKey($node.ToLower())) {
            $clNodeStates[$node.ToLower()]
        } else { 'Member (state unknown)' }
    }
    Write-Log ('    Cluster       : {0}' -f (if ($isClusterMember) { ('Member of {0} - State: {1}' -f $detectedCluster, $clState) } else { 'Standalone host' })) (if ($clState -eq 'Up' -or -not $isClusterMember) { 'OK' } else { 'WARN' })

    # --- Overall health ---
    $healthy = $ping -and $winrm -and $wmiBasic -and $wmiHyperV -and ($vmmsState -eq 'Running')
    $overallLevel = if ($healthy) { 'OK' } else { 'ERROR' }
    Write-Log ('    OVERALL       : {0}' -f (if ($healthy) { 'HEALTHY' } else { 'DEGRADED - see above' })) $overallLevel

    if (-not $healthy -and $isClusterMember) {
        Write-Log '    CLUSTER NOTE  : Fix this node before running Add-ClusterVirtualMachineRole.' 'WARN'
        Write-Log '                    All cluster nodes must have healthy Hyper-V WMI or role registration fails with "Invalid query".' 'WARN'
    }

    # Build issue summary string
    $issues = @()
    if (-not $winrm)                          { $issues += 'WinRM down' }
    if (-not $wmiBasic)                        { $issues += 'WMI cimv2 broken' }
    if (-not $wmiHyperV)                       { $issues += 'WMI HyperV broken' }
    if ($vmmsState -ne 'Running')              { $issues += ('VMMS {0}' -f $vmmsState) }
    if ($winmgmtState -ne 'Running')           { $issues += ('WinMgmt {0}' -f $winmgmtState) }
    $issueStr = if ($issues.Count -gt 0) { $issues -join '; ' } else { 'None' }

    # Build generic remediation string
    $remGeneric = @()
    $remCommand = @()
    if (-not $winrm) {
        $remGeneric += 'Enable WinRM / PSRemoting on node'
        $remCommand  += ('Invoke-Command -ComputerName {0} -ScriptBlock {{ Enable-PSRemoting -Force }}' -f $node)
    }
    if (-not $wmiHyperV -and $wmiBasic) {
        $remGeneric += 'Restart VMMS; re-register WMI DLLs if still broken'
        $remCommand  += ('Invoke-Command -ComputerName {0} -ScriptBlock {{ Restart-Service vmms -Force }}' -f $node)
    }
    if (-not $wmiBasic) {
        $remGeneric += 'Restart WMI service (winmgmt)'
        $remCommand  += ('Invoke-Command -ComputerName {0} -ScriptBlock {{ net stop winmgmt /y; net start winmgmt }}' -f $node)
    }
    if ($vmmsState -eq 'Stopped') {
        $remGeneric += 'Start VMMS service'
        $remCommand  += ('Invoke-Command -ComputerName {0} -ScriptBlock {{ Start-Service vmms }}' -f $node)
    } elseif ($vmmsState -notin @('Running','Unreachable','N/A')) {
        $remGeneric += ('Force kill stuck VMMS ({0})' -f $vmmsState)
        $remCommand  += ('Invoke-Command -ComputerName {0} -ScriptBlock {{ $p = Get-Process vmms -EA SilentlyContinue; if ($p) {{ Stop-Process -Id $p.Id -Force }}; Start-Sleep 3; Start-Service vmms }}' -f $node)
    }

    $nodeResults += [PSCustomObject]@{
        Node                = $node
        Ping                = if ($ping) { 'OK' } else { 'FAIL' }
        WinRM               = if ($winrm) { 'OK' } else { 'FAIL' }
        WMI_Basic           = if ($wmiBasic) { 'OK' } else { 'FAIL' }
        WMI_HyperV          = if ($wmiHyperV) { 'OK' } else { 'FAIL' }
        VMMS                = $vmmsState
        WinMgmt             = $winmgmtState
        ClusterMember       = if ($isClusterMember) { $detectedCluster } else { 'Standalone' }
        ClusterState        = $clState
        OS                  = $osCaption
        Healthy             = if ($healthy) { 'YES' } else { 'NO' }
        Issue               = $issueStr
        Remediation_Generic = ($remGeneric -join ' | ')
        Remediation_Command = ($remCommand -join ' ; ')
        Timestamp           = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    }
}

# ============================================================
# STEP 3: Cluster gap analysis (only when cluster specified)
# ============================================================
$gapResults = @()

if ($ClusterName -and -not $SkipClusterRoleCheck) {
    Write-Log ''
    Write-Log 'STEP 3: VM vs cluster role gap analysis' 'SECTION'

    # Registered cluster VM roles
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

    # VMs from WMI-healthy nodes only
    $allVMs = @()
    $healthyNodes = $nodeResults | Where-Object { $_.WMI_HyperV -eq 'OK' }
    foreach ($hn in $healthyNodes) {
        try {
            $vms = Get-VM -ComputerName $hn.Node -ErrorAction Stop
            foreach ($vm in $vms) {
                $allVMs += [PSCustomObject]@{
                    VMName = $vm.Name
                    State  = $vm.State.ToString()
                    Node   = $hn.Node
                }
            }
        } catch {}
    }
    Write-Log ('  VMs found across healthy nodes: {0}' -f $allVMs.Count)

    $unhealthyNodeCount = ($nodeResults | Where-Object { $_.WMI_HyperV -eq 'FAIL' }).Count
    if ($unhealthyNodeCount -gt 0) {
        Write-Log ('  WARNING: {0} node(s) had broken Hyper-V WMI - their VMs are NOT included in gap analysis.' -f $unhealthyNodeCount) 'WARN'
        Write-Log '           Fix degraded nodes and re-run for complete results.' 'WARN'
    }

    # Unregistered VMs
    Write-Log ''
    Write-Log '  --- Unregistered VMs (Hyper-V has VM, cluster does not) ---' 'SECTION'
    $foundUnreg = $false
    foreach ($vm in $allVMs) {
        if (-not $registeredGroups.ContainsKey($vm.VMName.ToLower())) {
            $foundUnreg = $true
            Write-Log ('  UNREGISTERED: {0} [{1}] on {2}' -f $vm.VMName, $vm.State, $vm.Node) 'WARN'

            # Only emit cluster command if node is confirmed cluster member
            $nodeIsCluster = ($nodeResults | Where-Object { $_.Node -eq $vm.Node }).ClusterMember -ne 'Standalone'
            if ($nodeIsCluster) {
                Write-Cmd 'Register as cluster role:' ('Add-ClusterVirtualMachineRole -VMName ''{0}'' -Cluster ''{1}''' -f $vm.VMName, $ClusterName)
                Write-Log '    NOTE: Ensure ALL cluster nodes have healthy Hyper-V WMI before running the above.' 'WARN'
            } else {
                Write-Log ('    NOTE: {0} appears to be a standalone host - cluster role registration not applicable.' -f $vm.Node) 'SKIP'
            }

            $regCmd = if ($nodeIsCluster) {
                ('Add-ClusterVirtualMachineRole -VMName ''{0}'' -Cluster ''{1}''' -f $vm.VMName, $ClusterName)
            } else {
                'N/A - standalone host'
            }

            $gapResults += [PSCustomObject]@{
                GapType             = 'Unregistered VM'
                VMName              = $vm.VMName
                Node                = $vm.Node
                VMState             = $vm.State
                CLGroup             = 'N/A'
                CLState             = 'N/A'
                CLOwner             = 'N/A'
                Remediation_Generic = 'VM exists in Hyper-V but has no cluster role - HA protection missing'
                Remediation_Command = $regCmd
                Timestamp           = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            }
        }
    }
    if (-not $foundUnreg) { Write-Log '  None found.' 'OK' }

    # Orphaned cluster groups
    Write-Log ''
    Write-Log '  --- Orphaned cluster groups (cluster has group, no backing VM found) ---' 'SECTION'
    $allVMNamesLower = $allVMs | ForEach-Object { $_.VMName.ToLower() }
    $foundOrphaned   = $false
    foreach ($key in $registeredGroups.Keys) {
        $grp       = $registeredGroups[$key]
        $cleanName = $grp.GroupName -replace '^SCVMM\s+', ''
        if ($cleanName.ToLower() -notin $allVMNamesLower -and
            $grp.GroupName.ToLower() -notin $allVMNamesLower) {
            $foundOrphaned = $true
            Write-Log ('  ORPHANED: "{0}" State={1} Owner={2}' -f $grp.GroupName, $grp.State, $grp.OwnerNode) 'WARN'
            Write-Log '    NOTE: Confirm VM is truly gone before removing. Check unhealthy nodes too.' 'WARN'
            Write-Cmd 'Remove orphaned group:' ('Remove-ClusterGroup -Cluster ''{0}'' -Name ''{1}'' -RemoveResources -Force' -f $ClusterName, $grp.GroupName)

            $gapResults += [PSCustomObject]@{
                GapType             = 'Orphaned Cluster Group'
                VMName              = 'N/A'
                Node                = $grp.OwnerNode
                VMState             = 'N/A'
                CLGroup             = $grp.GroupName
                CLState             = $grp.State
                CLOwner             = $grp.OwnerNode
                Remediation_Generic = 'Cluster group exists but no backing VM found on any healthy node - may be orphaned'
                Remediation_Command = ('Remove-ClusterGroup -Cluster ''{0}'' -Name ''{1}'' -RemoveResources -Force' -f $ClusterName, $grp.GroupName)
                Timestamp           = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            }
        }
    }
    if (-not $foundOrphaned) { Write-Log '  None found.' 'OK' }

    # Cluster group states (all)
    Write-Log ''
    Write-Log '  --- All cluster group states ---' 'SECTION'
    try {
        $allGroups = Get-ClusterGroup -Cluster $ClusterName -ErrorAction Stop | Sort-Object State, Name
        foreach ($grp in $allGroups) {
            $level = if ($grp.State -eq 'Online') { 'OK' } else { 'WARN' }
            Write-Log ('  {0,-48} {1,-10} Owner: {2}' -f $grp.Name, $grp.State, $grp.OwnerNode) $level

            if ($grp.State -eq 'Offline') {
                if ($grp.Name -eq 'Available Storage') {
                    Write-Cmd 'Bring Available Storage online:' ('Get-ClusterGroup -Cluster ''{0}'' -Name ''Available Storage'' | Start-ClusterGroup' -f $ClusterName)
                    Write-Cmd 'If disk resources are failed, check:' ('Get-ClusterResource -Cluster ''{0}'' | Where-Object {{ $_.OwnerGroup.Name -eq ''Available Storage'' }} | Select Name,State' -f $ClusterName)
                } elseif ($grp.Name -like '*CSV*' -or $grp.GroupType -eq 'SharedVolume') {
                    Write-Cmd 'Bring CSV group online:' ('Get-ClusterGroup -Cluster ''{0}'' -Name ''{1}'' | Start-ClusterGroup' -f $ClusterName, $grp.Name)
                } else {
                    Write-Cmd 'Bring group online:' ('Get-ClusterGroup -Cluster ''{0}'' -Name ''{1}'' | Start-ClusterGroup' -f $ClusterName, $grp.Name)
                }
            }
        }
    } catch {
        Write-Log ('  Failed to query cluster groups: {0}' -f $_) 'ERROR'
    }

} elseif (-not $ClusterName) {
    Write-Log ''
    Write-Log 'STEP 3: Cluster gap analysis skipped - no ClusterName specified.' 'SKIP'
} else {
    Write-Log ''
    Write-Log 'STEP 3: Cluster gap analysis skipped (-SkipClusterRoleCheck).' 'SKIP'
}

# ============================================================
# STEP 4: Final summary
# ============================================================
Write-Log ''
Write-Log ('=' * 70) 'SECTION'
Write-Log ' SUMMARY' 'SECTION'
Write-Log ('=' * 70) 'SECTION'

$degraded = $nodeResults | Where-Object { $_.Healthy -eq 'NO' }
$healthy  = $nodeResults | Where-Object { $_.Healthy -eq 'YES' }

Write-Log ('  Nodes checked  : {0}' -f $nodeResults.Count)
Write-Log ('  Healthy        : {0}' -f $healthy.Count) 'OK'
if ($degraded.Count -gt 0) {
    Write-Log ('  Degraded       : {0}' -f $degraded.Count) 'ERROR'
    foreach ($d in $degraded) {
        Write-Log ('    {0} : {1}' -f $d.Node, $d.Issue) 'ERROR'
    }
} else {
    Write-Log '  Degraded       : 0 - All nodes healthy' 'OK'
}

if ($gapResults.Count -gt 0) {
    $unregCount  = ($gapResults | Where-Object { $_.GapType -eq 'Unregistered VM'      }).Count
    $orphanCount = ($gapResults | Where-Object { $_.GapType -eq 'Orphaned Cluster Group' }).Count
    if ($unregCount -gt 0)  { Write-Log ('  Unregistered VMs      : {0}' -f $unregCount) 'WARN' }
    if ($orphanCount -gt 0) { Write-Log ('  Orphaned cluster groups: {0}' -f $orphanCount) 'WARN' }
} else {
    if ($ClusterName -and -not $SkipClusterRoleCheck) {
        Write-Log '  Role gaps      : None detected' 'OK'
    }
}

if ($degraded.Count -gt 0 -and $ClusterName) {
    Write-Log ''
    Write-Log '  *** IMPORTANT ***' 'ERROR'
    Write-Log '  Add-ClusterVirtualMachineRole will fail with "Invalid query" if ANY' 'ERROR'
    Write-Log '  cluster node has broken Hyper-V WMI. Remediate ALL degraded nodes' 'ERROR'
    Write-Log '  listed above before attempting cluster role registration.' 'ERROR'
}

# ============================================================
# EXPORT
# ============================================================
if (-not (Test-Path $ExportPath)) {
    New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
}

$ts        = Get-Date -Format 'yyyyMMdd_HHmmss'
$nodeRpt   = Join-Path $ExportPath "HVWMIHealth_Nodes_$ts.csv"
$gapRpt    = Join-Path $ExportPath "HVWMIHealth_Gaps_$ts.csv"

$nodeResults | Export-Csv -Path $nodeRpt -NoTypeInformation -Encoding UTF8
Write-Log ''
Write-Log ('  Node report : {0}' -f $nodeRpt) 'OK'

if ($gapResults.Count -gt 0) {
    $gapResults | Export-Csv -Path $gapRpt -NoTypeInformation -Encoding UTF8
    Write-Log ('  Gap report  : {0}' -f $gapRpt) 'OK'
}

Write-Log ('=' * 70) 'SECTION'
