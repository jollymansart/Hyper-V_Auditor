#Requires -Version 5.1
<#
.SYNOPSIS
    HyperVInventory sub-module: Cluster WMI Health audit tab.
    Produces data for three worksheets in the HyperVInventory Excel report.

.DESCRIPTION
    Designed to integrate with HyperVInventory.psm1 v3.10.x+
    Supports both standalone Hyper-V hosts and failover cluster nodes.
    Auto-detects cluster membership via MSCluster WMI namespace.
    Cluster-specific commands (Add-ClusterVirtualMachineRole, Remove-ClusterGroup,
    Start-ClusterGroup) are only emitted for confirmed cluster members.

    Worksheets produced:
      'Cluster WMI Health'  - Per-node ping/WMI/VMMS/cluster state
      'Cluster Role Gaps'   - Unregistered VMs + orphaned cluster groups
      'Cluster Groups'      - All cluster groups with state/owner/type

    Remediation columns (both sheets):
      Remediation_Generic : Plain-English description of the fix
      Remediation_Command : Exact copy-pasteable PowerShell command

.NOTES
    PS 5.1 compatible. Plain ASCII only. No Unicode.
    EPPlus cell index arithmetic: always wrap in parentheses before arithmetic.

    Integration in HyperVInventory.psm1 orchestrator:
        Import-Module '.\HyperVInventory.ClusterWMIHealth.psm1'
        $wmiHealth = Invoke-ClusterWMIHealthAudit -Nodes $AllNodes -ClusterName $ClusterName
        Add-ClusterWMIHealthSheets -Workbook $wb -AuditData $wmiHealth
#>

function _Get-SvcState {
    param([string]$ComputerName, [string]$ServiceName)
    try {
        $svc = Get-Service -ComputerName $ComputerName -Name $ServiceName -ErrorAction Stop
        return $svc.Status.ToString()
    } catch { return 'Unreachable' }
}

function _Get-ClusterMembership {
    param([string]$ComputerName)
    try {
        $cl = Get-WmiObject -ComputerName $ComputerName -Namespace 'root\MSCluster' `
                  -Class 'MSCluster_Cluster' -ErrorAction Stop | Select-Object -First 1
        if ($cl) { return $cl.Name } else { return '' }
    } catch { return '' }
}

function _Get-WmiHyperVHost {
    param([string]$ComputerName, [int]$TimeoutSec = 15)
    try {
        $job = Start-Job -ScriptBlock {
            param($cn)
            Get-WmiObject -ComputerName $cn -Namespace 'root\virtualization\v2' `
                -Class 'Msvm_ComputerSystem' -Filter "Caption='Hosting Computer System'" `
                -ErrorAction Stop | Select-Object -First 1
        } -ArgumentList $ComputerName
        $r = Wait-Job $job -Timeout $TimeoutSec | Receive-Job
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        return $r
    } catch { return $null }
}

function _SetHeader {
    param($Cell, [string]$Text)
    $Cell.Value = $Text
    $Cell.Style.Font.Bold = $true
    $Cell.Style.Font.Color.SetColor([System.Drawing.Color]::White)
    $Cell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
    $Cell.Style.Fill.BackgroundColor.SetColor([System.Drawing.ColorTranslator]::FromHtml('#203864'))
    $Cell.Style.Border.Bottom.Style = [OfficeOpenXml.Style.ExcelBorderStyle]::Thin
}

function _SetColor {
    param($Cell, [string]$HexFill, [string]$HexFont = '')
    $Cell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
    $Cell.Style.Fill.BackgroundColor.SetColor([System.Drawing.ColorTranslator]::FromHtml($HexFill))
    if ($HexFont) { $Cell.Style.Font.Color.SetColor([System.Drawing.ColorTranslator]::FromHtml($HexFont)) }
}

function _GetOrAddSheet {
    param($Workbook, [string]$Name)
    $ws = $Workbook.Workbook.Worksheets[$Name]
    if (-not $ws) { $ws = $Workbook.Workbook.Worksheets.Add($Name) }
    else          { $ws.Cells.Clear() }
    return $ws
}

# ============================================================
# PUBLIC: Main audit entry point
# ============================================================
function Invoke-ClusterWMIHealthAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string[]] $Nodes,
        [string] $ClusterName   = '',
        [int]    $WmiTimeoutSec = 15
    )

    $nodeHealth    = @()
    $roleGaps      = @()
    $clusterGroups = @()
    $auditTime     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $clNodeStates  = @{}
    $clNodeMembers = @{}
    if ($ClusterName) {
        try {
            $clNodes = Get-ClusterNode -Cluster $ClusterName -ErrorAction Stop
            foreach ($cn in $clNodes) {
                $clNodeStates[$cn.Name.ToLower()]  = $cn.State.ToString()
                $clNodeMembers[$cn.Name.ToLower()] = $true
            }
        } catch {}
    }

    foreach ($node in $Nodes) {
        $ping = Test-Connection -ComputerName $node -Count 1 -Quiet -ErrorAction SilentlyContinue

        $winrm = $false
        try { $w = Test-WSMan -ComputerName $node -ErrorAction Stop; $winrm = ($null -ne $w) } catch {}

        $wmiBasic = $false; $osCaption = ''
        try {
            $os = Get-WmiObject -ComputerName $node -Class Win32_OperatingSystem -ErrorAction Stop
            $wmiBasic = $true; $osCaption = $os.Caption
        } catch {}

        $wmiHyperV = $false
        $hvHost = _Get-WmiHyperVHost -ComputerName $node -TimeoutSec $WmiTimeoutSec
        if ($hvHost -and $hvHost.ElementName) { $wmiHyperV = $true }

        $vmmsState    = _Get-SvcState -ComputerName $node -ServiceName 'vmms'
        $winmgmtState = _Get-SvcState -ComputerName $node -ServiceName 'winmgmt'

        $isClusterMember = $false; $detectedCluster = ''
        if ($clNodeMembers.ContainsKey($node.ToLower())) {
            $isClusterMember = $true; $detectedCluster = $ClusterName
        } elseif ($wmiBasic) {
            $detectedCluster = _Get-ClusterMembership -ComputerName $node
            $isClusterMember = ($detectedCluster -ne '')
        }

        $clState = 'Standalone'
        if ($isClusterMember) {
            $clState = if ($clNodeStates.ContainsKey($node.ToLower())) { $clNodeStates[$node.ToLower()] } else { 'Member' }
        }

        $healthy = $ping -and $winrm -and $wmiBasic -and $wmiHyperV -and ($vmmsState -eq 'Running')

        $issues = @()
        if (-not $ping)               { $issues += 'Ping failed' }
        if (-not $winrm)              { $issues += 'WinRM down' }
        if (-not $wmiBasic)           { $issues += 'WMI cimv2 broken' }
        if (-not $wmiHyperV)          { $issues += 'WMI HyperV broken' }
        if ($vmmsState -ne 'Running') { $issues += ('VMMS {0}' -f $vmmsState) }
        if ($winmgmtState -ne 'Running') { $issues += ('WinMgmt {0}' -f $winmgmtState) }
        $issueStr = if ($issues.Count -gt 0) { $issues -join '; ' } else { 'None' }

        $remGeneric = @(); $remCommand = @()

        if (-not $ping) {
            $remGeneric += 'Node unreachable - verify power, NIC, and network path'
            $remCommand  += ('Test-NetConnection -ComputerName {0} -Port 5985' -f $node)
        }
        if ($ping -and -not $winrm) {
            $remGeneric += 'WinRM not configured or blocked'
            $remCommand  += ('Invoke-Command -ComputerName {0} -ScriptBlock {{ Enable-PSRemoting -Force }}' -f $node)
        }
        if (-not $wmiBasic -and $winrm) {
            $remGeneric += 'Base WMI (cimv2) broken - restart WMI service'
            $remCommand  += ('Invoke-Command -ComputerName {0} -ScriptBlock {{ net stop winmgmt /y; net start winmgmt }}' -f $node)
        }
        if (-not $wmiHyperV -and $wmiBasic) {
            $remGeneric += 'Hyper-V WMI provider broken - restart VMMS; re-register WMI DLLs if still broken'
            $remCommand  += ('Invoke-Command -ComputerName {0} -ScriptBlock {{ Restart-Service vmms -Force }}' -f $node)
        }
        if ($vmmsState -eq 'Stopped') {
            $remGeneric += 'VMMS stopped - start it'
            $remCommand  += ('Invoke-Command -ComputerName {0} -ScriptBlock {{ Start-Service vmms }}' -f $node)
        } elseif ($vmmsState -notin @('Running','Unreachable','N/A')) {
            $remGeneric += ('VMMS stuck in {0} - force kill and restart' -f $vmmsState)
            $remCommand  += ('Invoke-Command -ComputerName {0} -ScriptBlock {{ $p = Get-Process vmms -EA SilentlyContinue; if ($p) {{ Stop-Process -Id $p.Id -Force }}; Start-Sleep 3; Start-Service vmms }}' -f $node)
        }
        if ($winmgmtState -eq 'Stopped') {
            $remGeneric += 'WinMgmt stopped - start it'
            $remCommand  += ('Invoke-Command -ComputerName {0} -ScriptBlock {{ Start-Service winmgmt }}' -f $node)
        }
        if ($healthy) { $remGeneric += 'No action required'; $remCommand += 'N/A' }

        $nodeHealth += [PSCustomObject]@{
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
            AuditTime           = $auditTime
        }
    }

    # Gap analysis
    if ($ClusterName) {
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
        } catch {}

        $allVMs = @()
        foreach ($hn in ($nodeHealth | Where-Object { $_.WMI_HyperV -eq 'OK' })) {
            try {
                $vms = Get-VM -ComputerName $hn.Node -ErrorAction Stop
                foreach ($vm in $vms) {
                    $allVMs += [PSCustomObject]@{
                        VMName        = $vm.Name
                        State         = $vm.State.ToString()
                        Node          = $hn.Node
                        NodeIsCluster = ($hn.ClusterMember -ne 'Standalone')
                    }
                }
            } catch {}
        }

        $allVMNamesLower = $allVMs | ForEach-Object { $_.VMName.ToLower() }

        foreach ($vm in $allVMs) {
            if (-not $registeredGroups.ContainsKey($vm.VMName.ToLower())) {
                $regCmd = if ($vm.NodeIsCluster) {
                    ('Add-ClusterVirtualMachineRole -VMName ''{0}'' -Cluster ''{1}''' -f $vm.VMName, $ClusterName)
                } else { 'N/A - standalone host' }
                $roleGaps += [PSCustomObject]@{
                    GapType             = 'Unregistered VM'
                    VMName              = $vm.VMName
                    Node                = $vm.Node
                    VMState             = $vm.State
                    CLGroup             = 'N/A'; CLState = 'N/A'; CLOwner = 'N/A'
                    Remediation_Generic = 'VM exists in Hyper-V but has no cluster role - HA and live migration not available'
                    Remediation_Command = $regCmd
                    AuditTime           = $auditTime
                }
            }
        }

        foreach ($key in $registeredGroups.Keys) {
            $grp = $registeredGroups[$key]
            $cleanName = $grp.GroupName -replace '^SCVMM\s+', ''
            if ($cleanName.ToLower() -notin $allVMNamesLower -and $grp.GroupName.ToLower() -notin $allVMNamesLower) {
                $roleGaps += [PSCustomObject]@{
                    GapType             = 'Orphaned Cluster Group'
                    VMName              = 'N/A'; Node = $grp.OwnerNode; VMState = 'N/A'
                    CLGroup             = $grp.GroupName; CLState = $grp.State; CLOwner = $grp.OwnerNode
                    Remediation_Generic = 'Cluster group exists but no backing VM found - confirm VM is truly gone before removing'
                    Remediation_Command = ('Remove-ClusterGroup -Cluster ''{0}'' -Name ''{1}'' -RemoveResources -Force' -f $ClusterName, $grp.GroupName)
                    AuditTime           = $auditTime
                }
            }
        }

        try {
            foreach ($grp in (Get-ClusterGroup -Cluster $ClusterName -ErrorAction Stop | Sort-Object State, Name)) {
                $grpGeneric = ''; $grpCmd = ''
                if ($grp.State -ne 'Online') {
                    if ($grp.Name -eq 'Available Storage') {
                        $grpGeneric = 'Available Storage offline - disk resources may be failed or unclaimed'
                        $grpCmd = ('Get-ClusterGroup -Cluster ''{0}'' -Name ''Available Storage'' | Start-ClusterGroup' -f $ClusterName)
                    } else {
                        $grpGeneric = ('Cluster group offline - {0}' -f $grp.Name)
                        $grpCmd = ('Get-ClusterGroup -Cluster ''{0}'' -Name ''{1}'' | Start-ClusterGroup' -f $ClusterName, $grp.Name)
                    }
                } else { $grpGeneric = 'Online - no action required'; $grpCmd = 'N/A' }

                $clusterGroups += [PSCustomObject]@{
                    GroupName           = $grp.Name
                    State               = $grp.State.ToString()
                    OwnerNode           = $grp.OwnerNode.ToString()
                    GroupType           = $grp.GroupType.ToString()
                    Remediation_Generic = $grpGeneric
                    Remediation_Command = $grpCmd
                    AuditTime           = $auditTime
                }
            }
        } catch {}
    }

    return @{
        NodeHealth    = $nodeHealth
        RoleGaps      = $roleGaps
        ClusterGroups = $clusterGroups
        AuditTime     = $auditTime
        ClusterName   = $ClusterName
    }
}

# ============================================================
# PUBLIC: Write to Excel workbook (EPPlus)
# ============================================================
function Add-ClusterWMIHealthSheets {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Workbook,
        [Parameter(Mandatory)] [hashtable] $AuditData
    )

    # Sheet 1 - Node WMI Health
    $ws1 = _GetOrAddSheet -Workbook $Workbook -Name 'Cluster WMI Health'
    $ws1.Cells[1,1].Value = ('Hyper-V WMI Health - {0} - Audited {1}' -f (if ($AuditData.ClusterName) { $AuditData.ClusterName } else { 'Standalone Hosts' }), $AuditData.AuditTime)
    $ws1.Cells[1,1].Style.Font.Bold = $true; $ws1.Cells[1,1].Style.Font.Size = 13

    $h1 = @('Node','Ping','WinRM','WMI Basic','WMI HyperV','VMMS','WinMgmt','Cluster Member','Cluster State','OS','Healthy','Issue','Remediation (What)','Remediation (Command)','Audit Time')
    for ($c = 1; $c -le $h1.Count; $c++) { _SetHeader -Cell $ws1.Cells[3,$c] -Text $h1[($c - 1)] }

    $row = 4
    foreach ($nr in $AuditData.NodeHealth) {
        $vals = @($nr.Node,$nr.Ping,$nr.WinRM,$nr.WMI_Basic,$nr.WMI_HyperV,$nr.VMMS,$nr.WinMgmt,$nr.ClusterMember,$nr.ClusterState,$nr.OS,$nr.Healthy,$nr.Issue,$nr.Remediation_Generic,$nr.Remediation_Command,$nr.AuditTime)
        for ($c = 1; $c -le $vals.Count; $c++) { $ws1.Cells[$row,$c].Value = $vals[($c - 1)] }

        if ($nr.Healthy -eq 'YES') { _SetColor -Cell $ws1.Cells[$row,11] -HexFill '#92D050' }
        else                        { _SetColor -Cell $ws1.Cells[$row,11] -HexFill '#FF0000' -HexFont '#FFFFFF' }

        foreach ($c in @(2,3,4,5)) {
            $v = $ws1.Cells[$row,$c].Value
            if ($v -eq 'OK')   { _SetColor -Cell $ws1.Cells[$row,$c] -HexFill '#E2EFDA' }
            if ($v -eq 'FAIL') { _SetColor -Cell $ws1.Cells[$row,$c] -HexFill '#FFCCCC' }
        }
        if ($nr.VMMS -eq 'Running')    { _SetColor -Cell $ws1.Cells[$row,6] -HexFill '#E2EFDA' }
        elseif ($nr.VMMS -eq 'Stopped') { _SetColor -Cell $ws1.Cells[$row,6] -HexFill '#FFCCCC' }
        elseif ($nr.VMMS -notin @('Unreachable','N/A')) { _SetColor -Cell $ws1.Cells[$row,6] -HexFill '#FFF2CC' }

        if ($nr.ClusterState -eq 'Up')       { _SetColor -Cell $ws1.Cells[$row,9] -HexFill '#E2EFDA' }
        elseif ($nr.ClusterState -eq 'Down')  { _SetColor -Cell $ws1.Cells[$row,9] -HexFill '#FFCCCC' }

        $ws1.Cells[$row,14].Style.Font.Name = 'Consolas'
        $row = ($row + 1)
    }

    $row = ($row + 1)
    $hC = ($AuditData.NodeHealth | Where-Object { $_.Healthy -eq 'YES' }).Count
    $dC = ($AuditData.NodeHealth | Where-Object { $_.Healthy -eq 'NO'  }).Count
    $ws1.Cells[$row,1].Value = ('Healthy: {0}  /  Degraded: {1}' -f $hC, $dC)
    $ws1.Cells[$row,1].Style.Font.Bold = $true
    if ($dC -gt 0) { $ws1.Cells[$row,1].Style.Font.Color.SetColor([System.Drawing.ColorTranslator]::FromHtml('#FF0000')) }
    $row = ($row + 1)
    $ws1.Cells[$row,1].Value = 'NOTE: Add-ClusterVirtualMachineRole fails with "Invalid query" if ANY cluster node has broken Hyper-V WMI. Fix ALL degraded nodes before registering cluster roles.'
    $ws1.Cells[$row,1].Style.Font.Italic = $true
    $ws1.Cells[$row,1].Style.Font.Color.SetColor([System.Drawing.ColorTranslator]::FromHtml('#C00000'))

    $w1W = @(20,8,8,10,12,12,12,25,14,35,10,30,50,80,20)
    for ($c = 1; $c -le $w1W.Count; $c++) { $ws1.Column($c).Width = $w1W[($c - 1)] }

    # Sheet 2 - Role Gaps
    $ws2 = _GetOrAddSheet -Workbook $Workbook -Name 'Cluster Role Gaps'
    $ws2.Cells[1,1].Value = ('Cluster Role Gaps - {0} - Audited {1}' -f $AuditData.ClusterName, $AuditData.AuditTime)
    $ws2.Cells[1,1].Style.Font.Bold = $true; $ws2.Cells[1,1].Style.Font.Size = 13

    $h2 = @('Gap Type','VM Name','Node','VM State','Cluster Group','Cluster State','Cluster Owner','Remediation (What)','Remediation (Command)','Audit Time')
    for ($c = 1; $c -le $h2.Count; $c++) { _SetHeader -Cell $ws2.Cells[3,$c] -Text $h2[($c - 1)] }

    if ($AuditData.RoleGaps.Count -eq 0) {
        $ws2.Cells[4,1].Value = 'No gaps detected - all VMs registered, no orphaned groups.'
        $ws2.Cells[4,1].Style.Font.Bold = $true
        $ws2.Cells[4,1].Style.Font.Color.SetColor([System.Drawing.ColorTranslator]::FromHtml('#375623'))
    } else {
        $row = 4
        foreach ($gap in $AuditData.RoleGaps) {
            $vals = @($gap.GapType,$gap.VMName,$gap.Node,$gap.VMState,$gap.CLGroup,$gap.CLState,$gap.CLOwner,$gap.Remediation_Generic,$gap.Remediation_Command,$gap.AuditTime)
            for ($c = 1; $c -le $vals.Count; $c++) { $ws2.Cells[$row,$c].Value = $vals[($c - 1)] }
            $ws2.Cells[$row,9].Style.Font.Name = 'Consolas'
            $fill = if ($gap.GapType -eq 'Unregistered VM') { '#FFF2CC' } else { '#FFCCCC' }
            for ($c = 1; $c -le 10; $c++) { _SetColor -Cell $ws2.Cells[$row,$c] -HexFill $fill }
            $row = ($row + 1)
        }
    }
    $w2W = @(22,22,16,12,35,14,16,50,80,20)
    for ($c = 1; $c -le $w2W.Count; $c++) { $ws2.Column($c).Width = $w2W[($c - 1)] }

    # Sheet 3 - Cluster Groups
    $ws3 = _GetOrAddSheet -Workbook $Workbook -Name 'Cluster Groups'
    $ws3.Cells[1,1].Value = ('Cluster Groups - {0} - Audited {1}' -f $AuditData.ClusterName, $AuditData.AuditTime)
    $ws3.Cells[1,1].Style.Font.Bold = $true; $ws3.Cells[1,1].Style.Font.Size = 13

    $h3 = @('Group Name','State','Owner Node','Group Type','Remediation (What)','Remediation (Command)','Audit Time')
    for ($c = 1; $c -le $h3.Count; $c++) { _SetHeader -Cell $ws3.Cells[3,$c] -Text $h3[($c - 1)] }

    $row = 4
    foreach ($grp in $AuditData.ClusterGroups) {
        $vals = @($grp.GroupName,$grp.State,$grp.OwnerNode,$grp.GroupType,$grp.Remediation_Generic,$grp.Remediation_Command,$grp.AuditTime)
        for ($c = 1; $c -le $vals.Count; $c++) { $ws3.Cells[$row,$c].Value = $vals[($c - 1)] }
        $ws3.Cells[$row,6].Style.Font.Name = 'Consolas'
        if ($grp.State -eq 'Online')  { _SetColor -Cell $ws3.Cells[$row,2] -HexFill '#E2EFDA' }
        elseif ($grp.State -eq 'Offline') { _SetColor -Cell $ws3.Cells[$row,2] -HexFill '#FFCCCC' }
        else { _SetColor -Cell $ws3.Cells[$row,2] -HexFill '#FFF2CC' }
        $row = ($row + 1)
    }
    $w3W = @(45,12,18,18,50,80,20)
    for ($c = 1; $c -le $w3W.Count; $c++) { $ws3.Column($c).Width = $w3W[($c - 1)] }
}

Export-ModuleMember -Function Invoke-ClusterWMIHealthAudit, Add-ClusterWMIHealthSheets
