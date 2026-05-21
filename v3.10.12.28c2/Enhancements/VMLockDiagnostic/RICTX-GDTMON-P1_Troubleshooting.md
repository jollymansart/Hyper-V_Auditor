# RICTX-GDTMON-P1 VM Start Failure — Troubleshooting & Root Cause Analysis

**Author:** Michael George
**Date:** April 10, 2026
**Cluster:** RICTX-UCS-CLS
**Affected VM:** RICTX-GDTMON-P1
**CSV:** HV-Nimble4 (and HV-Nimble3 by extension)
**Status:** RESOLVED — VM recovered via node reboot + manual merge; CVDLP remediation pending

---

## Executive Summary

A Hyper-V VM (`RICTX-GDTMON-P1`) failed to start with error `0x80070020` ("The process cannot access the file because it is being used by another process") on a differencing disk (`.avhdx`). Initial investigation suggested an orphaned CommVault IntelliSnap/VSA backup checkpoint. Deeper diagnostics revealed **two related but distinct issues**:

1. **Acute issue (resolved):** A stuck kernel-mode file reference on cluster node **RICTX-UCSHV-P1** was preventing the background disk merge from completing. This handle was invisible to user-mode tools (`handle.exe`, `Get-SmbOpenFile`, `openfiles`) and persisted across the failed merge attempts P1 made at 8:58–9:00 AM. It was cleared only by evacuating VMs from P1 and rebooting the node.

2. **Underlying chronic issue (pending remediation):** The **CommVault Data Loss Prevention (CVDLP)** filter driver is attached to all Cluster Shared Volumes cluster-wide and is not CSV-compatible, placing every HV-Nimble* CSV into `IncompatibleFileSystemFilter` file-system redirected I/O mode on every node. This has been the case since CommVault was installed. CVDLP did not directly hold the file lock, but the forced redirected-mode I/O path made the background merge operation racy and susceptible to failure, creating the conditions under which the stuck kernel reference on P1 occurred.

**Resolution path taken:**

1. Evacuated all VMs from RICTX-UCSHV-P1 via Live Migration
2. Rebooted RICTX-UCSHV-P1 to clear stuck kernel-mode state
3. After reboot, the AVHDX file was accessible; manually merged the orphaned checkpoint back into the base VHDX
4. Reattached the base VHDX to the VM configuration
5. Started RICTX-GDTMON-P1 successfully

**Still outstanding:** CVDLP remediation across all cluster nodes (Section 7.2) to permanently clear the `IncompatibleFileSystemFilter` state and prevent recurrence.

---

## 1. Initial Error

```
'Virtual Machine RICTX-GDTMON-P1' failed to start.
'RICTX-GDTMON-P1' Synthetic SCSI Controller (Instance ID D3B85F40-D49E-4AA4-90F9-E69213A11190):
Failed to Power on with Error 'The process cannot access the file because it is being used by
another process.' (0x80070020).

'RICTX-GDTMON-P1': Attachment
'C:\ClusterStorage\HV-Nimble4\RICTX-GDTMON-P1\RICTX-GDTMON-P1\Virtual Hard Disks\
RICTX-GDTMON-P1_9E339AF7-90B7-4E25-98A0-F062E37786F6.avhdx' failed to open because of error:
'The process cannot access the file because it is being used by another process.' (0x80070020).

Cluster resource 'Virtual Machine RICTX-GDTMON-P1' failed. Error code '0x20'.
```

- **VM GUID:** `DFD2C5F7-24D7-42BD-9812-56F2E2522E8E`
- **Locked file:** `RICTX-GDTMON-P1_9E339AF7-90B7-4E25-98A0-F062E37786F6.avhdx`
- **CSV:** `HV-Nimble4`
- **Cluster resource state:** Failed

---

## 2. Initial Hypothesis — Stuck CommVault Checkpoint

The `_GUID.avhdx` naming pattern is characteristic of a CommVault IntelliSnap/VSA recovery checkpoint. Error `0x80070020` (`ERROR_SHARING_VIOLATION`) on this file type typically indicates one of the following:

1. A CommVault VSA backup job is still active or hung
2. An orphaned checkpoint from a failed backup that never merged
3. A CommVault filter driver or service retaining a file handle
4. Antivirus or security software scanning the file
5. Another cluster node retaining a handle after a failover race

---

## 3. Investigation — Phase 1

### 3.1 VM Configuration State

```powershell
Get-VM RICTX-GDTMON-P1 | Select-Object -ExpandProperty HardDrives | Format-List
Get-VM RICTX-GDTMON-P1 | Get-VMSnapshot
```

**Findings:**

| Property | Value |
|----------|-------|
| Attached disk (from config) | `RICTX-GDTMON-P1_9E339AF7-...avhdx` |
| Snapshots | **None** |
| VM state | Off |
| Owner node | RICTX-UCSHV-P2 |

The VM configuration points at the AVHDX differencing disk, but no snapshot exists in Hyper-V. This is the definitive signature of an **orphaned backup checkpoint** — the backup software (CommVault) created a checkpoint, took its backup, then failed to clean up and merge the checkpoint back into the base VHDX.

### 3.2 CSV Coordinator State

```powershell
Get-ClusterSharedVolume HV-Nimble4
```

| Name | State | Node |
|------|-------|------|
| HV-Nimble4 | Online(Redirected) | RICTX-UCSHV-P2 |

**Red flag:** The CSV is in **Online (Redirected)** mode, not normal Online mode. Redirected I/O means all file access must traverse the coordinator node over SMB rather than going direct to the block storage. This is abnormal and indicates either an active backup, a filter driver issue, or a path failure.

### 3.3 VM Folder File Listing

```
RICTX-GDTMON-P1.vhdx                                            32,484,884,480  4/9/2026  8:04:18 PM
RICTX-GDTMON-P1.vhdx.mrt                                                77,824  4/10/2026 4:07:32 AM
RICTX-GDTMON-P1.vhdx.rct                                             5,283,840  4/10/2026 4:07:32 AM
RICTX-GDTMON-P1_9E339AF7-...avhdx                                    4,194,304  4/10/2026 4:07:32 AM
RICTX-GDTMON-P1_9E339AF7-...avhdx.mrt                                   77,824  4/10/2026 4:07:32 AM
RICTX-GDTMON-P1_9E339AF7-...avhdx.rct                                   69,632  4/10/2026 4:07:32 AM
DFD2C5F7-24D7-42BD-9812-56F2E2522E8E.vmcx                              122,880  4/10/2026 9:02:06 AM
DFD2C5F7-24D7-42BD-9812-56F2E2522E8E.vmgs                            4,194,816  4/10/2026 3:48:13 AM
DFD2C5F7-24D7-42BD-9812-56F2E2522E8E.VMRS                               53,248  4/10/2026 9:17:48 AM
```

**Key observations:**
- `.mrt` and `.rct` files are CommVault **Resilient Change Tracking** files — definitive fingerprint of IntelliSnap/VSA backup activity.
- All CV tracking files and the AVHDX share a timestamp of **4:07:32 AM** on 4/10/2026 — this is when the backup job ran and failed.
- Base VHDX is ~32 GB; AVHDX is only 4 MB (minimal delta, since the VM was off most of the time).

### 3.4 Recent Event Log Findings

Multiple cluster nodes logged repeated failures:

```
Microsoft-Windows-Hyper-V-VMMS-Admin/19100:
'RICTX-GDTMON-P1' background disk merge failed to complete:
The process cannot access the file because it is being used by another process. (0x80070020).

System/1254:
Clustered role 'RICTX-GDTMON-P1' has exceeded its failover threshold.

System/21502:
'Virtual Machine RICTX-GDTMON-P1' failed to start.
```

The cluster was repeatedly failing the resource across nodes P1, P2, P6, P7, and P8, and Hyper-V VMMS was attempting **background disk merge** each time and failing with the same sharing violation. This is significant — Hyper-V itself was trying to auto-merge the orphan AVHDX.

---

## 4. Investigation — Phase 2 (Eliminating Suspects)

### 4.1 Open Handle Sweep (All Nodes)

```powershell
Get-SmbOpenFile | Where-Object Path -like "*RICTX-GDTMON-P1*"
openfiles /query /fo csv | findstr /i "GDTMON"
```

**Result:** No open handles found via SMB or `openfiles` on any node.

### 4.2 CommVault Service Restart on P2

Stopped all CommVault services on the CSV coordinator (P2):

```powershell
Get-Service Gx*, CVD* | Stop-Service -Force
```

All services stopped cleanly. **CSV remained in Online(Redirected) mode. `Get-VHD` still failed with "object is in use".** Stopping CommVault services did not resolve the issue.

### 4.3 VMMS / VMWP Process Audit

```powershell
$nodes = 'RICTX-UCSHV-P1','RICTX-UCSHV-P2','RICTX-UCSHV-P3','RICTX-UCSHV-P6','RICTX-UCSHV-P7','RICTX-UCSHV-P8'

Invoke-Command -ComputerName $nodes -ScriptBlock {
    Get-WmiObject Win32_Process -Filter "Name='vmwp.exe'" |
        Where-Object { $_.CommandLine -match 'DFD2C5F7-24D7-42BD-9812-56F2E2522E8E' }
}
```

**Result:** No `vmwp.exe` process on any node had the GDTMON VM GUID in its command line. No ghost worker process exists.

### 4.4 Sysinternals handle.exe on P2

```powershell
Invoke-WebRequest https://live.sysinternals.com/handle64.exe -OutFile C:\Windows\System32\handle.exe
handle.exe -accepteula -nobanner "RICTX-GDTMON-P1_9E339AF7"
```

**Result:** `No matching handles found.`

### 4.5 Key Realization

At this point, we have the following paradox:

- The AVHDX file is locked (confirmed by VMMS errors and `Get-VHD` failures)
- **No user-mode process** holds a handle on any node (handle.exe, openfiles, Get-SmbOpenFile all clean)
- CommVault services stopped on the coordinator did not release the lock
- No ghost `vmwp.exe` exists
- The CSV is persistently in redirected I/O mode

**Conclusion:** The lock is not a user-mode file handle. It is either kernel-mode (filter driver) or a CSVFS redirected I/O state issue. This required deeper inspection.

---

## 5. Investigation — Phase 3 (Root Cause)

### 5.1 CSV Redirection Reason

```powershell
Get-ClusterSharedVolumeState -Name HV-Nimble4 |
    Select Name, Node, StateInfo, FileSystemRedirectedIOReason, BlockRedirectedIOReason
```

**Result — all six nodes:**

```
Name                         : HV-Nimble4
StateInfo                    : FileSystemRedirected
FileSystemRedirectedIOReason : IncompatibleFileSystemFilter
BlockRedirectedIOReason      : NotBlockRedirected
```

`IncompatibleFileSystemFilter` is a specific Microsoft-defined reason code indicating that a file system minifilter is attached to the CSV volume which is **not marked as compatible with Cluster Shared Volumes direct I/O**. When CSVFS detects such a filter, it forces the entire volume into file-system redirected mode cluster-wide.

### 5.2 HV-Nimble3 Cross-Check

```powershell
Get-ClusterSharedVolumeState -Name HV-Nimble3
```

**Result:** HV-Nimble3 is **also** in `IncompatibleFileSystemFilter` redirected mode on all six nodes. This is not a single-volume problem — it is cluster-wide.

### 5.3 Filter Driver Enumeration

```powershell
Invoke-Command -ComputerName RICTX-UCSHV-P2 -ScriptBlock {
    fltmc instances -v C:\ClusterStorage\HV-Nimble4
}
```

**Result:**

| Filter | Altitude | Instance Name |
|--------|----------|---------------|
| FsDepends | 407000 | FsDepends |
| CCFFilter | 404600 | CCFFilter |
| WdFilter | 328010 | WdFilter Instance |
| storqosflt | 244000 | storqosflt |
| **CVDLP** | **145180** | **CVDLP.Encryption** |
| **CVDLP** | **85610** | **CVDLP.Shredding** |

**Root cause identified:** **CVDLP** — CommVault Data Loss Prevention — has two filter instances attached to the CSV: Encryption (altitude 145180) and Shredding (altitude 85610). CVDLP is not CSV-compatible and should not be running on a Hyper-V host.

### 5.4 MPIO / Block Storage Sanity Check

```powershell
Get-MPIOAvailableHW
mpclaim -s -d
```

**Result:** All Nimble LUNs showed healthy multipath state (`RRWS` load balancing policy, Microsoft DSM). No block-layer issue. `BlockRedirectedIOReason: NotBlockRedirected` confirms this independently.

---

## 6. Root Cause Analysis

### 6.1 What CVDLP Is

CommVault Data Loss Prevention (CVDLP) is a kernel-mode minifilter driver bundled with the CommVault agent that provides:

- **Encryption layer** — file-level encryption for data-at-rest protection
- **Shredding layer** — secure deletion of files beyond simple `delete` operations

It is intended for protecting file servers and endpoints, not hypervisors. On Hyper-V hosts, the VHDX files are already protected at the VM level by CommVault IntelliSnap/VSA backups — file-level encryption/shredding on the host adds no value and introduces serious compatibility problems.

### 6.2 Why It Breaks Clustered Storage

Windows file-system minifilters must opt in to CSV compatibility by declaring themselves cluster-aware in their driver registration. When CSVFS mounts a Cluster Shared Volume, it enumerates all attached minifilters and checks for the compatibility flag. If any attached filter lacks the flag, CSVFS forces the volume into **file-system redirected mode** (`IncompatibleFileSystemFilter`), which means:

- All I/O must traverse the coordinator node over SMB
- Direct block I/O from non-coordinator nodes is disabled
- File opens are serialized through the coordinator
- Performance is degraded cluster-wide
- Certain file operations (merges, opens during state transitions) become susceptible to timing races

### 6.3 Why the VM Won't Start

The failure sequence:

1. **4:07 AM** — CommVault IntelliSnap/VSA backup runs against RICTX-GDTMON-P1. It creates a Hyper-V recovery checkpoint (`_9E339AF7-...avhdx`) and backs it up.
2. **Backup completes** — CommVault issues a checkpoint-remove operation, which triggers Hyper-V's background disk merge to fold the AVHDX delta back into the base VHDX.
3. **Merge stalls** — Because the CSV is in `IncompatibleFileSystemFilter` redirected mode (due to CVDLP), the merge operation's file open path is serialized through the coordinator and wrapped in additional filter-driver processing. The operation fails partway through.
4. **Cluster failover attempts** — The cluster attempts to bring the VM online on successive nodes. Each attempt triggers VMMS to reopen the AVHDX chain. At approximately 8:58–9:00 AM, node **RICTX-UCSHV-P1** made attempts that left behind a stuck kernel-mode file reference on that node — likely a VMMS merge worker state, CSVFS file object, or filter-driver callback context that was not released after the failed open.
5. **Stuck kernel state on P1** — From that point forward, any node attempting to open the AVHDX hit `ERROR_SHARING_VIOLATION`, but `handle.exe`, `Get-SmbOpenFile`, and `openfiles` all reported no user-mode handle. The lock was in kernel memory on P1 specifically.
6. **Handle.exe sees nothing** — because the handle is not in a user-mode process handle table. Sysinternals `handle.exe` can only enumerate user-mode handles; it cannot see kernel-mode file object references held by drivers or the VMMS merge worker state machine.
7. **Only a reboot of P1 clears it** — Since no user-mode intervention can release a kernel-mode reference, the only way to clear the stuck state is to unload the kernel components holding it, which requires rebooting the specific node.

**Role of CVDLP in the failure:** CVDLP was not the direct holder of the file lock. However, by forcing the entire cluster into redirected I/O mode, CVDLP made the initial merge operation race-prone and failure-susceptible. Without CVDLP, CSVFS would have used direct I/O, the merge would likely have completed cleanly, and the stuck kernel state on P1 would never have occurred. CVDLP is therefore the **enabling condition** for this failure mode, even though it is not the proximate cause of the file lock itself.

### 6.4 Why This Has Been Invisible Until Now

The cluster has almost certainly been running with `IncompatibleFileSystemFilter` redirected mode **since CommVault was installed**. This manifests as:

- Reduced CSV I/O performance (everything goes through the coordinator)
- Occasional backup-related file issues
- Unexplained intermittent slowness

Until this specific combination of events (orphaned checkpoint + background merge + VM start attempt) triggered a hard failure, the problem was silent. VMs ran, backups "worked" (though likely slower than they should have), and nothing generated a critical alert about the filter compatibility issue.

---

## 7. Remediation

### 7.1 Immediate Recovery — Resolution Applied

**Status: COMPLETED. RICTX-GDTMON-P1 is running.**

The following steps were executed in sequence to recover the VM:

#### Step 1 — Evacuate RICTX-UCSHV-P1

All production VMs were Live Migrated off of node P1 to other nodes in the cluster. This was necessary because P1 was identified as the node holding the stuck kernel-mode reference on the GDTMON AVHDX file, and the only way to clear kernel state is a reboot.

```powershell
# Suspend the node with drain to move roles off
Suspend-ClusterNode -Name RICTX-UCSHV-P1 -Drain -Wait
```

#### Step 2 — Reboot RICTX-UCSHV-P1

```powershell
Restart-Computer -ComputerName RICTX-UCSHV-P1 -Wait -For PowerShell -Force
```

The reboot cleared the stuck kernel-mode file reference. After the reboot, the AVHDX file was accessible — `Get-VHD` returned information cleanly, confirming the lock was released.

#### Step 3 — Resume the node

```powershell
Resume-ClusterNode -Name RICTX-UCSHV-P1 -Failback Immediate
```

#### Step 4 — Manual merge of the orphaned checkpoint

With the file lock released, the orphaned AVHDX was manually merged back into the base VHDX:

```powershell
$base = "C:\ClusterStorage\HV-Nimble4\RICTX-GDTMON-P1\RICTX-GDTMON-P1\Virtual Hard Disks\RICTX-GDTMON-P1.vhdx"
$avhdx = "C:\ClusterStorage\HV-Nimble4\RICTX-GDTMON-P1\RICTX-GDTMON-P1\Virtual Hard Disks\RICTX-GDTMON-P1_9E339AF7-90B7-4E25-98A0-F062E37786F6.avhdx"

# Detach the broken AVHDX reference from the VM config
Get-VM RICTX-GDTMON-P1 | Get-VMHardDiskDrive | Remove-VMHardDiskDrive

# Merge the delta into the base
Merge-VHD -Path $avhdx -DestinationPath $base

# Reattach base VHDX
Add-VMHardDiskDrive -VMName RICTX-GDTMON-P1 -Path $base -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 0
```

#### Step 5 — Start the VM

```powershell
Start-ClusterGroup -Name RICTX-GDTMON-P1
```

The VM started successfully and returned to service.

#### Why this worked

The reboot of P1 was the critical step. No user-mode action (stopping CommVault services, killing processes, moving CSV ownership) was capable of releasing a kernel-mode file reference. Once P1 was rebooted, the kernel tables were clean and the file was available for merge. This confirms the diagnosis that the lock was held in kernel state on a specific node, not in any user-mode process.

#### Repair-VHDChain.ps1 Note

The existing `\\rictx-script-p2\Script_Dev\Powershell\Script\Hyper-V\Repair-VHDChain.ps1` script failed during this incident because it relies on `Get-VHD`, which itself opens the file and tripped the same sharing violation. This is an inherent limitation — any tool that calls `Get-VHD` against a locked VHDX will fail the same way. The script is valid for normal orphan-merge scenarios but cannot operate while a kernel-mode lock is in place. Future versions should detect this condition and advise the operator that a node reboot may be required.

### 7.2 Permanent Fix — Remove CVDLP from Hyper-V Hosts

**Priority: HIGH. Schedule as a change within the next maintenance window.**

CVDLP should not be installed on Hyper-V cluster nodes. It provides no value (VM-level backup already protects the VHDX files) and causes cluster-wide performance degradation plus the failure mode documented above.

#### Option A — Uninstall the CVDLP package (preferred)

1. Open CommVault CommCell Console
2. Navigate to each cluster node client
3. Advanced → Install/Upgrade Software → Uninstall
4. Select "Data Loss Prevention" package
5. Uninstall **one node at a time**, with cluster drain before each uninstall:

```powershell
# For each node, in sequence:
$node = 'RICTX-UCSHV-P1'
Suspend-ClusterNode -Name $node -Drain -Wait
# ... uninstall CVDLP via CommCell Console ...
# Reboot if required by the uninstaller
Restart-Computer -ComputerName $node -Wait -For PowerShell -Force
Resume-ClusterNode -Name $node -Failback Immediate
# Verify CSV state before moving to next node
Get-ClusterSharedVolumeState -Name HV-Nimble4 | Select Node, StateInfo, FileSystemRedirectedIOReason
```

#### Option B — Exclude CSV paths from CVDLP

If CVDLP is actually protecting something valid on these hosts (verify in CommCell Console first), add a path exclusion for `C:\ClusterStorage\*` in the CVDLP subclient configuration. Requires CVD service restart on each node.

#### Option C — Upgrade CommVault agent

Newer CommVault agent versions may have resolved this by making CVDLP CSV-compatible or by not attaching to CSV volumes by default. Check current version:

```powershell
Invoke-Command -ComputerName RICTX-UCSHV-P2 -ScriptBlock {
    Get-ItemProperty 'HKLM:\SOFTWARE\CommVault Systems\Galaxy\Instance001\InstalledPackages' -ErrorAction SilentlyContinue |
        Select sBinaryVersion, sProductVersion
}
```

Open a CommVault support case with the `fltmc` output and the `IncompatibleFileSystemFilter` state to confirm the recommended remediation for your agent version.

### 7.3 Validation After Remediation

After CVDLP is removed from any node, verify the fix:

```powershell
# 1. Filter should be absent
Invoke-Command -ComputerName RICTX-UCSHV-P1 -ScriptBlock {
    fltmc instances -v C:\ClusterStorage\HV-Nimble4
}
# Expected: No CVDLP entries

# 2. CSV should report NotFileSystemRedirected
Get-ClusterSharedVolumeState -Name HV-Nimble4 |
    Select Name, Node, StateInfo, FileSystemRedirectedIOReason
# Expected: StateInfo = Direct, FileSystemRedirectedIOReason = NotFileSystemRedirected
# (once ALL nodes have CVDLP removed)

# 3. Get-VHD should work against VM files
Get-VHD "C:\ClusterStorage\HV-Nimble4\RICTX-GDTMON-P1\RICTX-GDTMON-P1\Virtual Hard Disks\RICTX-GDTMON-P1.vhdx"
# Expected: Returns VHD info without errors
```

Until all nodes have CVDLP removed, the CSV will remain in redirected mode — the flag is cluster-wide and set whenever **any** node has the incompatible filter attached.

---

## 8. Lessons Learned & Preventive Actions

### 8.1 Monitoring Gaps

The cluster has been running in `IncompatibleFileSystemFilter` redirected mode cluster-wide since CommVault was installed, and no alert ever fired. Monitoring should be added:

```powershell
# Proposed monitoring check — run on a schedule
Get-ClusterSharedVolume | Get-ClusterSharedVolumeState |
    Where-Object FileSystemRedirectedIOReason -ne 'NotFileSystemRedirected' |
    Select Name, Node, StateInfo, FileSystemRedirectedIOReason
```

Any result from this query should trigger an alert to the infrastructure team. Add this to the SolarWinds monitoring suite or the HyperV Inventory Report suite as a compliance check.

### 8.2 HyperV Inventory Report Suite Enhancement

Add a new module `HyperVInventory-CSVHealth.psm1` that reports:

- Per-CSV state and redirection reason
- Attached filter drivers with altitudes (via `fltmc`)
- Known-incompatible filter detection (CVDLP, legacy AV products, CBT drivers)
- Historical tracking of CSV state changes

This would have caught the CVDLP issue on day one.

### 8.3 CommVault Agent Review

Review all CommVault packages installed on Hyper-V cluster nodes and remove any that are not strictly required:

- **Keep:** Hyper-V VSA agent (`Virtual Server Agent`), base File System iDataAgent (if used for host-level backup)
- **Remove:** CVDLP, any Exchange/SQL/SharePoint agents not applicable, any DLP or eDiscovery components

### 8.4 Change Tracking Files

The `.mrt` and `.rct` files that remained after the failed backup should be cleaned up by CommVault automatically. If they persist, it indicates a pattern of failed backups that needs investigation. Add a weekly job to scan CSV VM folders for stale CV tracking files older than 24 hours.

### 8.5 Kernel-Mode File Locks Are Invisible to User-Mode Tools

A critical lesson from this incident: **`handle.exe`, `Get-SmbOpenFile`, and `openfiles` cannot see kernel-mode file references.** All three tools only enumerate user-mode handle tables. When a driver, VMMS merge worker, CSVFS state machine, or filter driver holds a file object reference in kernel memory, these tools report "no handles found" even though the file is unambiguously locked.

**When to suspect a kernel-mode lock:**

- File is locked (`ERROR_SHARING_VIOLATION` on open)
- No user-mode handle found via any of the standard tools
- Stopping related services does not release the lock
- The lock persists across user-mode process restarts
- Moving CSV ownership does not clear it

**When this pattern appears, the only reliable remediation is:**

1. Identify which node holds the kernel state (usually the last node that attempted the failed operation)
2. Evacuate VMs/workloads from that node
3. Reboot the node
4. Retry the operation after the reboot

No amount of user-mode troubleshooting will release a kernel-mode reference. Recognizing this pattern early would have saved significant investigation time in this incident.

### 8.6 Repair-VHDChain.ps1 Limitation

The existing `Repair-VHDChain.ps1` tool on `\\rictx-script-p2\Script_Dev\Powershell\Script\Hyper-V\` relies on `Get-VHD` to walk the VHD chain. `Get-VHD` itself opens the VHDX file, which trips the same `ERROR_SHARING_VIOLATION` when the file is locked. As a result, the tool cannot operate against a VM suffering from this failure mode — it fails at the chain-building step before it can attempt any repair.

**Proposed enhancement:**

Add a pre-flight check that:
1. Attempts `Get-VHD` with a short timeout
2. On `ObjectInUse` error, switches to parsing the VHDX header directly (without opening through the storage stack) to identify parent paths
3. Reports the failure mode clearly and advises the operator that a node reboot may be required
4. Optionally, identifies the likely lock-holding node from recent event log entries

---

## 9. Diagnostic Tool — Invoke-VMLockDiagnostic.ps1

A PowerShell diagnostic script was developed during this troubleshooting session to automate the investigation:

**Location:** `\\rictx-script-p2\Script_Dev\Powershell\Script\Hyper-V\Invoke-VMLockDiagnostic.ps1`
**Version:** 1.0.0 (v1.1 planned)

### 9.1 What It Does

- Identifies cluster, VM resource, and CSV coordinator node
- Reports VM configuration, hard drive chain, and snapshot state
- Detects orphaned AVHDX (config references AVHDX but no snapshot exists)
- Lists VM folder contents with CommVault fingerprint detection
- Sweeps all cluster nodes for open file handles (SMB + handle.exe)
- Reports CommVault service state per node
- Collects recent Hyper-V VMMS and cluster events related to the VM GUID
- Generates recommendations and saves a JSON report to `\\rictx-script-p2\LOG\Hyper-V\`

### 9.2 Planned v1.1 Enhancements

- `fltmc instances` output per CSV with filter driver enumeration
- Known-incompatible filter detection (CVDLP, legacy AV)
- `Get-ClusterSharedVolumeState` with `FileSystemRedirectedIOReason` highlighted
- Fix empty-array handling bug in snapshot reporting
- Cluster-wide CSV health summary
- Filter driver altitude analysis

### 9.3 Usage

```powershell
\\rictx-script-p2\Script_Dev\Powershell\Script\Hyper-V\Invoke-VMLockDiagnostic.ps1 -VMName RICTX-GDTMON-P1
```

---

## 10. Timeline

| Time (4/10/2026) | Event |
|------------------|-------|
| ~4:07:32 AM | CommVault IntelliSnap/VSA backup runs, creates AVHDX checkpoint, backup completes but merge fails |
| 2:05 AM – 8:06 AM | Cluster repeatedly attempts to fail over and start RICTX-GDTMON-P1 on nodes P6, P7, P8 |
| 8:58 – 9:00 AM | Further failover attempts on P1; **stuck kernel-mode file reference left behind on P1**; cluster exceeds failover threshold, VM left in Failed state |
| 9:17 – 9:18 AM | User investigation begins; initial diagnostics |
| ~9:20 AM | Diagnostic script v1.0 developed and run |
| ~9:30 AM | Handle sweep across all nodes — no user-mode handles found |
| ~9:45 AM | CSV redirection reason identified: `IncompatibleFileSystemFilter` |
| ~9:50 AM | `fltmc instances` reveals CVDLP as contributing factor |
| ~10:00 AM | Decision made to reboot P1 after confirming no user-mode remediation possible |
| ~10:15 AM | VMs evacuated from RICTX-UCSHV-P1 via Live Migration |
| ~10:25 AM | RICTX-UCSHV-P1 rebooted; stuck kernel state cleared |
| ~10:30 AM | Node resumed; AVHDX file accessible; manual merge performed |
| ~10:35 AM | RICTX-GDTMON-P1 started successfully — **incident resolved** |
| Pending | CVDLP removal across all cluster nodes (Section 7.2) |

---

## 11. References

- Microsoft Docs: [Cluster Shared Volumes I/O Redirected Mode](https://learn.microsoft.com/en-us/windows-server/failover-clustering/failover-cluster-csvs)
- Microsoft Docs: [File System Minifilter Drivers — CSV Support](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/creating-minifilter-drivers)
- Sysinternals: [handle.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/handle)
- CommVault: Data Loss Prevention package documentation (refer to local CommVault support)

---

*Document generated as part of the RICTX-UCS-CLS cluster troubleshooting case, April 10, 2026.*
