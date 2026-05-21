<#
.SYNOPSIS
    Get-VMShutdownAnalysis.ps1
    Starter script for VM shutdown/activity forensics.
    Will be expanded into full VM Activity Audit module.

.DESCRIPTION
    Queries Hyper-V Worker, VMMS, System, and FailoverClustering logs
    for a specific VM over the last 48 hours.

.NOTES
    Author: Michael George | Version: 0.1.0 (starter) | Date: 2026-03-24
    Target: Expand into Invoke-VMActivityAudit function with trigger correlation.

    Event Log Locations:
      Event Viewer -> Applications and Services Logs -> Microsoft -> Windows -> Hyper-V-Worker -> Admin
      Event Viewer -> Windows Logs -> System
      Event Viewer -> Applications and Services Logs -> Microsoft -> Windows -> FailoverClustering -> Operational
      Event Viewer -> Applications and Services Logs -> Microsoft -> Windows -> Hyper-V-VMMS -> Admin

    Trigger Matrix:
      A user         -> User32 1074 events / VMMS 14020 "shutdown initiated" / Worker 18501 "guest initiated shutdown"
      The guest OS   -> 6006/6008/41 inside the VM / integration services shutdown events
      The cluster    -> 1069, 1135, 1254, 21502, 20500 / cluster resource movement
      The host OS    -> 41, 6006, 6008 in the host System log / reboot / power loss
      A worker crash -> VMMS 4096 / Worker 18503

    Quick one-liner to check a specific VMID:
      $vmId = '49A49BD8-5885-4E85-BFC5-929EB2A0C2D3'
      Get-WinEvent -LogName 'Microsoft-Windows-Hyper-V-Worker-Admin' |
        Where-Object { $_.Message -like "*$vmId*" } |
        Select-Object TimeCreated, Id, LevelDisplayName, Message |
        Sort-Object TimeCreated -Descending
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$VMName
)

# Resolve VM ID
$vm = Get-VM -Name $VMName -ErrorAction Stop
$vmId = $vm.Id.Guid
Write-Host "Analyzing shutdown activity for VM: $VMName ($vmId)" -ForegroundColor Cyan

# Time window (last 48 hours by default)
$start = (Get-Date).AddDays(-2)

# Collect logs
$worker = Get-WinEvent -LogName 'Microsoft-Windows-Hyper-V-Worker-Admin' -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -like "*$vmId*" -and $_.TimeCreated -gt $start }

$vmms = Get-WinEvent -LogName 'Microsoft-Windows-Hyper-V-VMMS-Admin' -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -like "*$vmId*" -and $_.TimeCreated -gt $start }

$system = Get-WinEvent -LogName System -ErrorAction SilentlyContinue |
    Where-Object {
        $_.TimeCreated -gt $start -and
        ($_.Id -in 41,6006,6008,1074)
    }

$cluster = Get-WinEvent -LogName 'Microsoft-Windows-FailoverClustering/Operational' -ErrorAction SilentlyContinue |
    Where-Object {
        $_.TimeCreated -gt $start -and
        ($_.Message -like "*$VMName*" -or $_.Message -like "*$vmId*")
    }

# Merge and sort
$events = @($worker + $vmms + $system + $cluster) |
    Sort-Object TimeCreated

# Output
$events | Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message
