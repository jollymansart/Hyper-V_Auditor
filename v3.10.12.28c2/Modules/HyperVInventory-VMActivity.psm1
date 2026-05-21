<#
.SYNOPSIS
    HyperV Inventory - VM Activity Audit Module (Session 14)

.DESCRIPTION
    Collects VM lifecycle events from Hyper-V hosts: shutdowns, power-ons, power-offs,
    snapshot create/delete, resource changes, cluster failovers. Correlates each event
    with a trigger (human, guest OS, cluster, host, backup, automation).

.NOTES
    Author: Michael George
    Version: 3.10.12
    Date: April 11, 2026
    CR85: Broadened Event ID collection -- no ID filter on VMMS/Worker logs,
          classify post-collection. Added infrastructure Event IDs (16300, 10103,
          12240, 15268, 19070, 19080). Unknown IDs get descriptive labels instead
          of being skipped.
    CR93: Enhanced trigger classification for 18500/18502 (Host unclean/forced
          stop) and descriptive CorrelatedEvents labels via switch table.
    CR95: ForensicNote column + 8 new event IDs (14070, 15140, 12148, 12582,
          12597, 18609, 18601, 4092). VMName regex false-positive filter.
    CR96: Event-ID-specific VMName extraction dispatcher. Event 20400 (VM
          Replication) now uses targeted regex to extract VM name from
          "for virtual machine 'X'" pattern instead of the first quoted string
          (which is the replica partner address). Fixes 481 events/run showing
          replica partner IPs in VMName column.
    CR97: New EventMessage column (truncated to 500 chars). Captures raw event
          text so analysts can see what the event actually said when parsing
          fails or produces unexpected results.
    CR98: New ReplicaPartner column. Populated only for Event 20400 with the
          replica source address extracted from the message.
    CR99: Event 20400 AlertLevel reclassification based on message content.
          "Failed to authenticate" / "Kerberos" = Warning. "could not connect"
          / "connection refused" = Critical. Otherwise Info.
#>

function Invoke-VMActivityAudit {
    <#
    .SYNOPSIS
        Collects VM lifecycle events from Hyper-V hosts with trigger correlation.

    .PARAMETER HostData
        Array of completed host objects from the inventory collection.

    .PARAMETER DaysBack
        Number of days of event history to collect. Default: 7.

    .PARAMETER CorrelationWindowSec
        Seconds +/- to search for correlated trigger events. Default: 30.

    .OUTPUTS
        Array of PSCustomObject rows for the VM-Activity-Audit tab.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$HostData,

        [Parameter(Mandatory = $false)]
        [int]$DaysBack = 7,

        [Parameter(Mandatory = $false)]
        [int]$CorrelationWindowSec = 30,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    $startDate = (Get-Date).AddDays(-$DaysBack)

    # v3.10.6 CR85: Broadened Event ID maps to include all known Hyper-V event IDs.
    # The original v3.10.2 filter missed environment-specific IDs (16300, 10103, 12240,
    # 15268, 19070, 19080) that are common in production but not documented as "lifecycle".
    # Now we collect ALL events from each log (no ID filter) and classify post-collection.
    # Known IDs get descriptive labels; unknown IDs get "VMMS Event NNNNN" / "Worker Event NNNNN".
    $vmmsEvents = @{
        13000 = 'VM Created'
        13002 = 'VM Created (import)'
        12300 = 'VM Started'
        12302 = 'VM Started (restored)'
        12304 = 'VM Stopped (by host)'
        14020 = 'VM Shutdown Initiated'
        18600 = 'Snapshot Created'
        18602 = 'Snapshot Created (auto)'
        18610 = 'Snapshot Deleted'
        18612 = 'Snapshot Merged'
        # v3.10.6 CR85: Infrastructure events discovered in OHDC environment
        16300 = 'VM Config Load Failure'
        10103 = 'VM Management Service Event'
        12240 = 'VHD Attachment Not Found'
        15268 = 'Disk Info Retrieval Failure'
        19070 = 'Background Disk Merge Started'
        19080 = 'Background Disk Merge Completed'
        13003 = 'VM Deleted'
        13260 = 'VM Configuration Updated'
        14092 = 'VM State Changed'
        20400 = 'VM Replication Event'
        18504 = 'VM Reset'
        # v3.10.9 CR95: Additional VMMS events from forensic analysis
        14070 = 'VMMS State Change Initiated'
        15140 = 'VM Configuration Change'
    }
    $workerEvents = @{
        18500 = 'VM Powered Off'
        18501 = 'VM Shutdown (guest-initiated)'
        18502 = 'VM Powered Off (forced)'
        18503 = 'VM Worker Crashed'
        # v3.10.9 CR95: Worker events from forensic analysis (host-side crash/restart indicators)
        12148 = 'VM State Transition Failure'
        12582 = 'Critical Worker Process Error'
        12597 = 'Device/Storage Attachment Error'
        18609 = 'Host Forced Power-Off (vmwp crash)'
        18601 = 'VM Started (by host worker)'
        4092  = 'Worker State Change Notification'
    }

    # v3.10.9 CR95: Forensic-grade interpretation for key events
    # Provides root-cause context for each event ID, shown in a new ForensicNote column.
    $forensicNotes = @{
        # Worker events -- host-side indicators
        12148 = 'State transition failure: VM was trying to start/stop/save/restore and something blocked it. Common causes: VHDX inaccessible, CSV latency, checkpoint merge conflict, config file lock.'
        12582 = 'CRITICAL internal worker error (vmwp.exe). Integration services crash, synthetic device failure, memory map corruption, or hypervisor partition glitch. Major red flag -- VM was already failing internally.'
        12597 = 'Device/storage attachment error. VM tried to access a disk or controller and failed. Suggests storage instability: VHDX I/O stall, storage path timeout, controller reset, CSV redirected I/O.'
        18609 = 'HOST FORCED POWER-OFF. The host worker process (vmwp.exe) forcibly terminated the VM. This is the host-side equivalent of guest Event 6008. Causes: storage I/O stall, vmwp.exe crash, host instability, cluster forced termination.'
        18601 = 'VM started by host worker process. Confirms the HOST restarted the VM, not the guest OS. Often follows 18609 (auto-restart after crash).'
        18500 = 'VM powered off. High-level state change -- does not indicate WHY. Check correlated events for root cause.'
        18501 = 'Guest-initiated shutdown. The guest OS cleanly initiated the shutdown from inside the VM.'
        18502 = 'Forced power-off. VM was forcibly stopped without clean shutdown. Check for preceding 12148/12582/12597 which indicate storage/worker failure.'
        18503 = 'VM worker process (vmwp.exe) crashed. The hypervisor-level process managing this VM terminated unexpectedly.'
        18504 = 'VM was reset (equivalent to pressing the reset button). No clean shutdown occurred.'
        4092  = 'Worker state change notification (informational). Logs for every internal VM state transition. Not an error, but useful as a timeline marker. Excessive 4092 spam suggests rapid state transitions during failure.'
        # VMMS events
        14070 = 'VMMS initiated a state change (start/stop/reset/save). If near a shutdown event, an admin or system component initiated it. If not paired with shutdown, unrelated.'
        15140 = 'VM configuration change occurred (informational). Someone or something modified VM settings. Not related to shutdown events.'
        16300 = 'VM configuration load failure. Hyper-V could not load the VM configuration file. May indicate corrupt .vmcx or permission issues.'
        12240 = 'VHD attachment not found. The VM references a VHDX that no longer exists or is inaccessible at the configured path.'
        15268 = 'Disk information retrieval failure. Hyper-V could not query disk metadata. Often accompanies storage path issues.'
        19070 = 'Background disk merge started (informational). Checkpoint AVHDX being merged into parent VHDX. Normal post-checkpoint operation.'
        19080 = 'Background disk merge completed (informational). Checkpoint merge finished successfully.'
        13003 = 'VM deleted from Hyper-V inventory.'
        13260 = 'VM configuration updated (informational). Settings changed via Hyper-V Manager, SCVMM, or PowerShell.'
        14092 = 'VM state changed (informational). Generic state transition log entry.'
        12304 = 'VM stopped by host (VMMS-initiated stop, not guest-initiated).'
        # Cluster events
        1069  = 'Cluster resource went offline. May indicate failover in progress.'
        1254  = 'Cluster resource group moved to another node. Planned or unplanned migration.'
        21502 = 'Live migration started. VM being moved between cluster nodes.'
    }
    $clusterEvents = @{
        1069  = 'Resource moved (failover)'
        1135  = 'Node removed from cluster'
        1254  = 'Resource group moved'
        21502 = 'Live migration started'
        20500 = 'Resource moved online'
        1230  = 'Node joined cluster'
    }

    foreach ($hostObj in $HostData) {
        if ($hostObj.Error) { continue }
        $hostName = $hostObj.HostName
        $hostFQDN = if ($hostObj.FQDN) { $hostObj.FQDN } else { $hostName }
        $hostCluster = if ($hostObj.ClusterInfo -and $hostObj.ClusterInfo.ClusterName) {
            $hostObj.ClusterInfo.ClusterName
        } else { '' }

        # Build VM ID -> Name lookup from current inventory
        $vmIdLookup = @{}
        if ($hostObj.VMs) {
            foreach ($vm in $hostObj.VMs) {
                if ($vm.VMId) { $vmIdLookup[$vm.VMId.ToUpper()] = $vm.VM }
            }
        }

        Write-HVLog "  VM Activity: querying $hostFQDN (last $DaysBack days)..." -Level Info

        try {
            $credParam = @{}
            if ($hostObj.EffectiveCredential) {
                $credParam['Credential'] = $hostObj.EffectiveCredential
            }
            elseif ($Credential) {
                $credParam['Credential'] = $Credential
            }

            # Collect events from the host via WinRM
            # v3.10.6 CR85: VMMS and Worker logs are collected WITHOUT ID filtering.
            # The original ID filter caused 0 events because the environment uses different
            # Event IDs than those documented. We collect all events and classify afterward.
            # System and Cluster logs keep their ID filters (those logs are huge otherwise).
            $eventData = Invoke-Command -ComputerName $hostFQDN @credParam -ErrorAction Stop -ScriptBlock {
                param($startDate, $clusterIds, $maxEventsPerLog)

                $allEvents = [System.Collections.Generic.List[object]]::new()

                # VMMS Admin log -- NO ID filter (CR85)
                try {
                    $vmmsLog = Get-WinEvent -FilterHashtable @{
                        LogName   = 'Microsoft-Windows-Hyper-V-VMMS-Admin'
                        StartTime = $startDate
                    } -MaxEvents $maxEventsPerLog -ErrorAction SilentlyContinue
                    if ($vmmsLog) {
                        foreach ($e in $vmmsLog) {
                            $allEvents.Add(@{
                                Time      = $e.TimeCreated
                                Source    = 'VMMS-Admin'
                                EventID   = $e.Id
                                Message   = $e.Message
                                User      = if ($e.UserId) { try { ([System.Security.Principal.SecurityIdentifier]$e.UserId).Translate([System.Security.Principal.NTAccount]).Value } catch { $e.UserId.Value } } else { '' }
                                VMName    = ''
                                VMID      = ''
                            })
                        }
                    }
                } catch {}

                # Worker Admin log -- NO ID filter (CR85)
                try {
                    $workerLog = Get-WinEvent -FilterHashtable @{
                        LogName   = 'Microsoft-Windows-Hyper-V-Worker-Admin'
                        StartTime = $startDate
                    } -MaxEvents $maxEventsPerLog -ErrorAction SilentlyContinue
                    if ($workerLog) {
                        foreach ($e in $workerLog) {
                            $allEvents.Add(@{
                                Time      = $e.TimeCreated
                                Source    = 'Worker-Admin'
                                EventID   = $e.Id
                                Message   = $e.Message
                                User      = ''
                                VMName    = ''
                                VMID      = ''
                            })
                        }
                    }
                } catch {}

                # System log - shutdown/reboot events (keep ID filter -- System log is huge)
                try {
                    $sysLog = Get-WinEvent -FilterHashtable @{
                        LogName   = 'System'
                        StartTime = $startDate
                        ID        = @(41, 1074, 6005, 6006, 6008, 6009)
                    } -ErrorAction SilentlyContinue
                    if ($sysLog) {
                        foreach ($e in $sysLog) {
                            $allEvents.Add(@{
                                Time      = $e.TimeCreated
                                Source    = 'System'
                                EventID   = $e.Id
                                Message   = $e.Message
                                User      = if ($e.UserId) { try { ([System.Security.Principal.SecurityIdentifier]$e.UserId).Translate([System.Security.Principal.NTAccount]).Value } catch { '' } } else { '' }
                                VMName    = ''
                                VMID      = ''
                            })
                        }
                    }
                } catch {}

                # Failover Clustering log (keep ID filter)
                try {
                    $clsLog = Get-WinEvent -FilterHashtable @{
                        LogName   = 'Microsoft-Windows-FailoverClustering/Operational'
                        StartTime = $startDate
                        ID        = $clusterIds
                    } -ErrorAction SilentlyContinue
                    if ($clsLog) {
                        foreach ($e in $clsLog) {
                            $allEvents.Add(@{
                                Time      = $e.TimeCreated
                                Source    = 'FailoverClustering'
                                EventID   = $e.Id
                                Message   = $e.Message
                                User      = ''
                                VMName    = ''
                                VMID      = ''
                            })
                        }
                    }
                } catch {}

                return $allEvents
            } -ArgumentList @(
                $startDate,
                @($clusterEvents.Keys),
                500   # maxEventsPerLog -- cap per log to prevent runaway on noisy hosts
            )

            if (-not $eventData -or $eventData.Count -eq 0) {
                Write-Verbose "  $hostFQDN : no VM activity events in last $DaysBack days"
                continue
            }

            Write-Verbose "  $hostFQDN : $($eventData.Count) raw events collected"

            # Sort events by time for correlation
            $sortedEvents = @($eventData | Sort-Object { $_.Time })

            # Process VM-related events (VMMS + Worker)
            foreach ($evt in $sortedEvents) {
                $evtSource = $evt.Source
                $evtID     = $evt.EventID
                $evtTime   = $evt.Time
                $evtMsg    = if ($evt.Message) { $evt.Message.ToString() } else { '' }
                $evtUser   = $evt.User

                # Skip System/Cluster events as primary - they're used for correlation only
                if ($evtSource -in @('System', 'FailoverClustering')) { continue }

                # Determine activity -- v3.10.6 CR85: Unknown IDs now get a descriptive label
                # instead of being silently skipped. This ensures ALL VMMS/Worker events appear.
                $activity = ''
                if ($vmmsEvents.ContainsKey($evtID)) { $activity = $vmmsEvents[$evtID] }
                elseif ($workerEvents.ContainsKey($evtID)) { $activity = $workerEvents[$evtID] }
                else { $activity = "$evtSource Event $evtID" }

                # Extract VM name from message (VMMS/Worker events typically contain it)
                # v3.10.9 CR95: Filter out false matches -- disk paths, ": Attachment", GUIDs,
                # and other quoted strings that are not VM display names.
                # v3.10.10 CR96: Event-ID-specific VMName extraction dispatcher.
                #   Event 20400 (VM Replication) has a different message structure where the
                #   first quoted string is the replica partner address, not the VM name. Example:
                #     "Failed to authenticate the Replica server '10.91.1.157' using Kerberos
                #      authentication for virtual machine 'VM-NAME'"
                #   Generic regex was grabbing '10.91.1.157' as the VMName across 481 events/run.
                # v3.10.10 CR98: Extract replica partner address into a dedicated variable for
                #   Event 20400 so it appears in its own column, not the VMName column.
                $vmName         = ''
                $replicaPartner = ''

                if ($evtID -eq 20400) {
                    # --- Event 20400 (VM Replication) targeted extraction ---
                    # Primary: "for virtual machine 'X'" pattern (strongest signal)
                    if ($evtMsg -match "for virtual machine '([^']+)'") {
                        $vmName = $Matches[1]
                    }
                    elseif ($evtMsg -match "on virtual machine '([^']+)'") {
                        $vmName = $Matches[1]
                    }
                    elseif ($evtMsg -match "virtual machine '([^']+)'") {
                        $vmName = $Matches[1]
                    }
                    # Extract replica partner (the FIRST quoted string in 20400 messages is
                    # typically "Replica server 'ADDRESS'" or similar)
                    if ($evtMsg -match "[Rr]eplica server '([^']+)'") {
                        $replicaPartner = $Matches[1]
                    }
                    elseif ($evtMsg -match "[Rr]eplica(?:\s+\w+)?\s+'([^']+)'") {
                        $replicaPartner = $Matches[1]
                    }
                    elseif ($evtMsg -match "'([^']+)'") {
                        # Fallback: first quoted string (but only if it doesn't match the VM
                        # name we already extracted above, to avoid populating both fields
                        # with the same value)
                        if ($Matches[1] -ne $vmName) {
                            $replicaPartner = $Matches[1]
                        }
                    }
                    # NOTE: Do NOT fall through to generic regex below -- generic regex would
                    # set VMName back to the replica partner address.
                }
                else {
                    # --- Generic extraction for all other event IDs (CR95 logic preserved) ---
                    if ($evtMsg -match "'([^']+)'") {
                        $candidate = $Matches[1]
                        # Filter out non-VM-name matches
                        if ($candidate -notmatch '^\s*:\s|\\\\|\.vhdx?$|\.avhdx?$|\.vmcx$|^[A-F0-9]{8}-|Attachment|controller|adapter|disk|drive|port' -and
                            $candidate.Length -gt 1 -and $candidate.Length -lt 80) {
                            $vmName = $candidate
                        }
                    }
                    if (-not $vmName -and $evtMsg -match '"([^"]+)"') {
                        $candidate = $Matches[1]
                        if ($candidate -notmatch '^\s*:\s|\\\\|\.vhdx?$|\.avhdx?$|\.vmcx$|^[A-F0-9]{8}-|Attachment|controller|adapter|disk|drive|port' -and
                            $candidate.Length -gt 1 -and $candidate.Length -lt 80) {
                            $vmName = $candidate
                        }
                    }
                }

                # Resolve VM ID if present in message
                $vmId = ''
                if ($evtMsg -match '([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})') {
                    $vmId = $Matches[1].ToUpper()
                    if (-not $vmName -and $vmIdLookup.ContainsKey($vmId)) {
                        $vmName = $vmIdLookup[$vmId]
                    }
                }

                # --- Trigger correlation ---
                # Look +/- correlation window for trigger events
                $trigger       = 'Unknown'
                $triggerDetail = ''
                $triggerUser   = $evtUser
                $triggerProcess = ''
                $correlatedIDs = @()

                # Check for guest-initiated
                if ($evtID -eq 18501) {
                    $trigger       = 'Guest OS'
                    $triggerDetail = 'Shutdown initiated from inside the VM'
                }
                elseif ($evtID -eq 18503) {
                    $trigger       = 'Worker Crash'
                    $triggerDetail = 'Hyper-V worker process crashed'
                }
                else {
                    # Search correlation window
                    $windowStart = $evtTime.AddSeconds(-$CorrelationWindowSec)
                    $windowEnd   = $evtTime.AddSeconds($CorrelationWindowSec)

                    $correlatedEvents = @($sortedEvents | Where-Object {
                        $_.Time -ge $windowStart -and $_.Time -le $windowEnd -and
                        $_.Source -ne $evtSource
                    })

                    foreach ($corr in $correlatedEvents) {
                        # v3.10.9 CR93: Descriptive correlated event labels instead of raw Source:ID
                        $corrLabel = switch ("$($corr.Source):$($corr.EventID)") {
                            'System:1074'           { 'User-initiated shutdown (1074)' }
                            'System:41'             { 'Unexpected host shutdown (41)' }
                            'System:6005'           { 'Event log started (6005)' }
                            'System:6006'           { 'Clean host shutdown (6006)' }
                            'System:6008'           { 'Previous unexpected shutdown (6008)' }
                            'System:6009'           { 'OS version info at boot (6009)' }
                            'FailoverClustering:1069' { 'Cluster resource offline (1069)' }
                            'FailoverClustering:1254' { 'Cluster group moved (1254)' }
                            'FailoverClustering:20500' { 'Cluster validation (20500)' }
                            'FailoverClustering:21502' { 'Live migration (21502)' }
                            'FailoverClustering:1230'  { 'Node joined cluster (1230)' }
                            'VMMS-Admin:19070'      { 'Background disk merge started (19070)' }
                            'VMMS-Admin:19080'      { 'Background disk merge completed (19080)' }
                            'VMMS-Admin:18500'      { 'VM powered off (18500)' }
                            'VMMS-Admin:18501'      { 'VM shutdown guest-initiated (18501)' }
                            'VMMS-Admin:18502'      { 'VM forced power-off (18502)' }
                            'VMMS-Admin:18504'      { 'VM reset (18504)' }
                            'VMMS-Admin:12514'      { 'VM state change (12514)' }
                            'VMMS-Admin:13002'      { 'VM checkpoint operation (13002)' }
                            'VMMS-Admin:16300'      { 'VM config load failure (16300)' }
                            'VMMS-Admin:14070'      { 'VMMS state change initiated (14070)' }
                            'VMMS-Admin:15140'      { 'VM configuration change (15140)' }
                            'VMMS-Admin:14092'      { 'VM state changed (14092)' }
                            'VMMS-Admin:13260'      { 'VM configuration updated (13260)' }
                            'Worker-Admin:4092'     { 'Worker state change (4092, informational)' }
                            'Worker-Admin:12148'    { 'VM state transition FAILURE (12148, storage/CSV)' }
                            'Worker-Admin:12582'    { 'CRITICAL worker process error (12582, vmwp.exe)' }
                            'Worker-Admin:12597'    { 'Device/storage attachment ERROR (12597)' }
                            'Worker-Admin:18609'    { 'HOST FORCED POWER-OFF (18609, vmwp crash)' }
                            'Worker-Admin:18601'    { 'VM started by host worker (18601, auto-restart)' }
                            'Worker-Admin:18500'    { 'VM powered off (18500)' }
                            'Worker-Admin:18501'    { 'VM shutdown guest-initiated (18501)' }
                            'Worker-Admin:18502'    { 'VM forced power-off (18502)' }
                            'Worker-Admin:18503'    { 'VM worker CRASHED (18503)' }
                            default                 { "$($corr.Source):$($corr.EventID)" }
                        }
                        $correlatedIDs += $corrLabel

                        # User32 1074 = user-initiated shutdown
                        if ($corr.EventID -eq 1074 -and $corr.Source -eq 'System') {
                            $trigger = 'Human (interactive)'
                            $triggerUser = $corr.User
                            if ($corr.Message -match 'process\s+(\S+)') {
                                $triggerProcess = $Matches[1]
                            }
                            $triggerDetail = "User $triggerUser via $triggerProcess"
                        }
                        # Cluster failover
                        elseif ($corr.Source -eq 'FailoverClustering') {
                            if ($corr.EventID -in @(1069, 1254, 20500)) {
                                $trigger = 'Cluster (failover)'
                                $triggerDetail = "Cluster resource movement (Event $($corr.EventID))"
                            }
                            elseif ($corr.EventID -eq 21502) {
                                $trigger = 'Cluster (live migration)'
                                $triggerDetail = 'Live migration initiated'
                            }
                        }
                        # Host reboot
                        elseif ($corr.EventID -in @(41, 6006, 6008) -and $corr.Source -eq 'System') {
                            $trigger = 'Host OS'
                            $triggerDetail = if ($corr.EventID -eq 41) { 'Unexpected host shutdown (kernel power)' }
                                             elseif ($corr.EventID -eq 6006) { 'Clean host shutdown' }
                                             elseif ($corr.EventID -eq 6008) { 'Previous unexpected shutdown detected' }
                                             else { "System event $($corr.EventID)" }
                        }
                    }

                    # If still unknown but has a user, it's likely automation/service
                    if ($trigger -eq 'Unknown' -and $triggerUser) {
                        if ($triggerUser -match 'svc_|service|system|SYSTEM') {
                            $trigger = 'Service/Automation'
                            $triggerDetail = "Service account: $triggerUser"
                        }
                        else {
                            $trigger = 'Human (interactive)'
                            $triggerDetail = "User: $triggerUser"
                        }
                    }

                    # v3.10.9 CR93: Enhanced classification for VM power events
                    # When Event 18500 (VM Powered Off) or 18502 (forced) remain Unknown after
                    # correlation, it usually means the host VMMS stopped the VM without a
                    # guest-initiated shutdown or cluster action. Common causes:
                    #   - Heartbeat integration service timeout (host killed unresponsive VM)
                    #   - Backup software (CommVault/Veeam) power-cycling the VM
                    #   - Host memory pressure or resource starvation
                    #   - Scheduled host maintenance scripts
                    if ($trigger -eq 'Unknown' -and $evtID -in @(18500, 18502)) {
                        # Check if the event message contains heartbeat clues
                        if ($evtMsg -match 'heartbeat|not responding|timed out|lost communication') {
                            $trigger = 'Host (heartbeat timeout)'
                            $triggerDetail = 'VM stopped responding to heartbeat integration service'
                        }
                        elseif ($evtID -eq 18502) {
                            # Forced power-off with no correlated events = host-initiated kill
                            $trigger = 'Host (forced stop)'
                            $triggerDetail = 'VMMS forced VM power-off -- check host event logs, backup schedules, and resource pressure'
                        }
                        else {
                            # 18500 with no trigger = host-initiated or unclean
                            $trigger = 'Host (unclean stop)'
                            $triggerDetail = 'VM powered off without guest-initiated shutdown -- check heartbeat, backup schedules, host health'
                        }
                    }

                    # v3.10.9 CR95: Event 18609 is the definitive indicator of host-forced power-off.
                    # The host worker process (vmwp.exe) forcibly terminated the VM. This is the
                    # host-side equivalent of guest Event 6008. No admin action, no guest-initiated
                    # shutdown. Usually preceded by 12148 + 12597 + 12582 (storage/worker distress).
                    if ($evtID -eq 18609) {
                        $trigger = 'Host (vmwp forced power-off)'
                        $triggerDetail = 'HOST FORCED POWER-OFF via worker process crash. Check: storage I/O stalls, CSV latency, VHDX access timeout, vmwp.exe instability'
                    }
                    # 18601 = host auto-restarted the VM after a crash
                    if ($trigger -eq 'Unknown' -and $evtID -eq 18601) {
                        $trigger = 'Host (auto-restart)'
                        $triggerDetail = 'VM auto-restarted by host worker process after previous crash/power-off'
                    }
                }

                # Alert level
                $alertLevel = switch ($activity) {
                    'VM Powered Off (forced)' { 'Critical' }
                    'VM Worker Crashed'       { 'Critical' }
                    'Host Forced Power-Off (vmwp crash)' { 'Critical' }
                    'Critical Worker Process Error'      { 'Critical' }
                    'VM Reset'                { 'Warning' }
                    'VM Config Load Failure'  { 'Warning' }
                    'VHD Attachment Not Found' { 'Warning' }
                    'Disk Info Retrieval Failure' { 'Warning' }
                    'VM State Transition Failure'         { 'Warning' }
                    'Device/Storage Attachment Error'     { 'Warning' }
                    'VM Powered Off'          { if ($trigger -eq 'Unknown') { 'Warning' } else { 'Info' } }
                    'VM Shutdown (guest-initiated)' { 'Info' }
                    'VM Started'              { 'Info' }
                    'VM Started (restored)'   { 'Info' }
                    'VM Started (by host worker)' { 'Info' }
                    'Snapshot Created'        { 'Info' }
                    'Snapshot Created (auto)' { 'Info' }
                    'Snapshot Deleted'        { 'Info' }
                    'Snapshot Merged'         { 'Info' }
                    'Background Disk Merge Started'    { 'Info' }
                    'Background Disk Merge Completed'  { 'Info' }
                    'VM Management Service Event'      { 'Info' }
                    'VM Configuration Updated'         { 'Info' }
                    'VM Configuration Change'          { 'Info' }
                    'VMMS State Change Initiated'      { 'Info' }
                    'Worker State Change Notification'  { 'Info' }
                    'VM Created'              { 'Info' }
                    'VM Created (import)'     { 'Info' }
                    'VM Deleted'              { 'Warning' }
                    default                   { 'Info' }
                }
                if ($trigger -eq 'Host OS' -and $triggerDetail -match 'Unexpected') { $alertLevel = 'Critical' }
                if ($trigger -eq 'Cluster (failover)') { $alertLevel = 'Warning' }

                # v3.10.10 CR99: Event 20400 AlertLevel reclassification based on message content.
                # Default activity-based mapping treats 20400 as 'Info' which masks ongoing
                # replication authentication failures. Re-classify based on keywords in the raw
                # event message:
                #   Critical: "could not connect" / "connection refused" / "unreachable"
                #   Warning : "Failed to authenticate" / "authentication failed" / "Kerberos"
                #             / "access denied" / "cannot access"
                #   Info    : everything else (successful checkpoint, state change, etc.)
                if ($evtID -eq 20400) {
                    if ($evtMsg -match '(?i)could not connect|connection refused|unreachable|could not reach') {
                        $alertLevel = 'Critical'
                    }
                    elseif ($evtMsg -match '(?i)failed to authenticate|authentication failed|kerberos|access denied|cannot access|access is denied') {
                        $alertLevel = 'Warning'
                    }
                    else {
                        $alertLevel = 'Info'
                    }
                }

                # v3.10.10 CR97: Truncate raw event message to 500 chars for EventMessage column.
                # Remove embedded newlines/carriage returns so the cell stays single-line in Excel.
                $truncatedMsg = ''
                if ($evtMsg) {
                    $cleanedMsg = ($evtMsg -replace '\r?\n', ' ' -replace '\s+', ' ').Trim()
                    if ($cleanedMsg.Length -gt 500) {
                        $truncatedMsg = $cleanedMsg.Substring(0, 497) + '...'
                    } else {
                        $truncatedMsg = $cleanedMsg
                    }
                }

                $rows.Add([PSCustomObject]@{
                    Timestamp        = if ($evtTime) { $evtTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                    VMName           = $vmName
                    Host             = $hostName
                    ClusterName      = $hostCluster
                    Activity         = $activity
                    Trigger          = $trigger
                    TriggerDetail    = $triggerDetail
                    UserAccount      = $triggerUser
                    ProcessName      = $triggerProcess
                    EventSource      = $evtSource
                    EventID          = $evtID
                    EventMessage     = $truncatedMsg            # CR97: truncated raw event text
                    ReplicaPartner   = $replicaPartner          # CR98: replica source for Event 20400 only
                    ForensicNote     = if ($forensicNotes.ContainsKey($evtID)) { $forensicNotes[$evtID] } else { '' }
                    CorrelatedEvents = if ($correlatedIDs.Count -gt 0) { ($correlatedIDs | Select-Object -Unique) -join '; ' } else { '' }
                    AlertLevel       = $alertLevel
                })
            }

            Write-HVLog "  VM Activity: $hostFQDN -- $($rows.Count) events processed" -Level Info

        }
        catch {
            Write-HVLog "  VM Activity: $hostFQDN -- collection error: $($_.Exception.Message)" -Level Warning
        }
    }

    Write-HVLog "  VM Activity Audit complete: $($rows.Count) events across $($HostData.Count) hosts" -Level Info
    return $rows
}

Export-ModuleMember -Function @(
    'Invoke-VMActivityAudit'
)
