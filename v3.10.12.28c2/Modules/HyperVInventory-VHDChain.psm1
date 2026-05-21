#Requires -Version 5.1
# HyperVInventory-VHDChain.psm1
# Version: 3.10.12
# CR105: VHD Parent Chain Visibility + Consolidation Recommendations
#
# Walks the ParentPath chain for every VHD attached to every VM on every host.
# One row per chain link (Active / Checkpoint / Base / Passthrough / BrokenParent / Error).
# Provides ChainDepth, ChainTotalMB, AlertLevel, Recommendation per link.
# Is the authoritative source for AvhdxChainDepth used by the vCheckpoint tab (CR104).
# Feeds CR106 (New-VMRemediationScript) for per-VM repair script generation.
#
# Collection uses a remote scriptblock run via Invoke-Command on each Hyper-V host.
# Uses Test-Path before Get-VHD to avoid storage timeouts on broken parent references.
# Does NOT run on the management host -- all chain walking happens on the target host.


function Invoke-VHDChainCollection {
    <#
    .SYNOPSIS
        Collects the full VHD parent chain for every disk on every running VM
        across a list of Hyper-V hosts.  CR105 implementation.

    .DESCRIPTION
        For each host in CompletedHosts, runs a remote scriptblock that walks
        the ParentPath chain for every VHD attached to every VM.  Returns one
        PSObject row per chain link with structured metadata.

        Collection is I/O cheap -- reads only file metadata (Get-VHD, Get-Item),
        not VHD data.  Expected overhead: 50-200ms per disk per host.

        Uses Test-Path before each Get-VHD call to avoid indefinite hangs on
        broken or inaccessible parent paths (common with Commvault stuck chains).

        Passthrough disks (no .vhdx/.avhdx extension) are emitted as single rows
        with LinkType = 'Passthrough' and ChainDepth = 1.

    .PARAMETER CompletedHosts
        Array of host data objects from the main inventory collection.
        Each object must have .HostName, .FQDN, and .VMs (array of VM objects).

    .PARAMETER Credential
        Primary WinRM credential.  Used when DomainCredentials has no entry for
        the host's domain.

    .PARAMETER DomainCredentials
        Hashtable[domainFQDN -> PSCredential] for multi-domain environments.

    .PARAMETER Config
        Parsed Config.psd1 hashtable.  Reads VHDChainWarningDepth,
        VHDChainCriticalDepth, VHDChainStaleCheckpointDays.

    .OUTPUTS
        [System.Collections.Generic.List[PSObject]]  one row per chain link
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$CompletedHosts,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [hashtable]$DomainCredentials = @{},

        [Parameter(Mandatory=$false)]
        [hashtable]$Config = @{}
    )

    # Thresholds -- read from config with safe defaults matching master plan spec
    $warnDepth  = if ($Config.VHDChainWarningDepth)       { [int]$Config.VHDChainWarningDepth }       else { 3 }
    $critDepth  = if ($Config.VHDChainCriticalDepth)      { [int]$Config.VHDChainCriticalDepth }      else { 5 }
    $staleDays  = if ($Config.VHDChainStaleCheckpointDays){ [int]$Config.VHDChainStaleCheckpointDays } else { 7 }

    $allResults = [System.Collections.Generic.List[PSObject]]::new()

    # Remote scriptblock -- runs on each Hyper-V host.
    # Accepts a list of VM display names to scope the query.
    # Returns raw chain link data before alerting/recommendation logic is applied
    # (alerting happens locally so config values don't have to cross the remoting boundary).
    $sb = {
        param([string[]]$vmNames)

        $links = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($vmName in $vmNames) {
            $vm = $null
            try {
                $vm = Hyper-V\Get-VM -Name $vmName -ErrorAction Stop
            }
            catch { continue }

            foreach ($hd in $vm.HardDrives) {
                $diskPath = $hd.Path
                if (-not $diskPath) { continue }

                $ctrlType = $hd.ControllerType.ToString()
                $ctrlNum  = $hd.ControllerNumber
                $ctrlLoc  = $hd.ControllerLocation

                # Passthrough disk -- no file to walk
                if ($diskPath -notmatch '\.(a?vhdx?)$') {
                    $links.Add(@{
                        VMName         = $vmName
                        ControllerType = $ctrlType
                        ControllerNum  = $ctrlNum
                        ControllerLoc  = $ctrlLoc
                        ChainLevel     = 0
                        LinkType       = 'Passthrough'
                        FilePath       = $diskPath
                        FileSizeMB     = 0
                        FileFormat     = 'Passthrough'
                        ParentPath     = ''
                        CreatedOn      = $null
                        IsBaseDisk     = $true
                        Error          = ''
                    })
                    continue
                }

                # Walk the chain from leaf (active .avhdx) to base (.vhdx)
                $level  = 0
                $chain  = [System.Collections.Generic.List[hashtable]]::new()
                $curPath = $diskPath
                $keepGoing = $true

                while ($keepGoing) {
                    # Test-Path first to avoid Get-VHD hanging on broken parent paths
                    if (-not (Test-Path -LiteralPath $curPath -ErrorAction SilentlyContinue)) {
                        $chain.Add(@{
                            VMName         = $vmName
                            ControllerType = $ctrlType
                            ControllerNum  = $ctrlNum
                            ControllerLoc  = $ctrlLoc
                            ChainLevel     = $level
                            LinkType       = 'BrokenParent'
                            FilePath       = $curPath
                            FileSizeMB     = 0
                            FileFormat     = 'Unknown'
                            ParentPath     = ''
                            CreatedOn      = $null
                            IsBaseDisk     = $false
                            Error          = "Test-Path returned False: file not found or inaccessible"
                        })
                        break
                    }

                    $vhd = $null
                    try {
                        $vhd = Get-VHD -Path $curPath -ErrorAction Stop
                    }
                    catch {
                        $chain.Add(@{
                            VMName         = $vmName
                            ControllerType = $ctrlType
                            ControllerNum  = $ctrlNum
                            ControllerLoc  = $ctrlLoc
                            ChainLevel     = $level
                            LinkType       = if ($level -eq 0) { 'Error' } else { 'BrokenParent' }
                            FilePath       = $curPath
                            FileSizeMB     = 0
                            FileFormat     = 'Unknown'
                            ParentPath     = ''
                            CreatedOn      = $null
                            IsBaseDisk     = $false
                            Error          = "Get-VHD failed: $($_.Exception.Message)"
                        })
                        break
                    }

                    $fi       = Get-Item -LiteralPath $curPath -ErrorAction SilentlyContinue
                    $sizeMB   = if ($fi) { [math]::Round($fi.Length / 1MB, 2) } else { 0 }
                    $created  = if ($fi) { $fi.CreationTime } else { $null }
                    $linkType = if ($level -eq 0)                              { 'Active'     }
                               elseif ($curPath -match '\.avhdx?$')            { 'Checkpoint' }
                               elseif (-not $vhd.ParentPath)                   { 'Base'       }
                               else                                            { 'Checkpoint' }

                    $chain.Add(@{
                        VMName         = $vmName
                        ControllerType = $ctrlType
                        ControllerNum  = $ctrlNum
                        ControllerLoc  = $ctrlLoc
                        ChainLevel     = $level
                        LinkType       = $linkType
                        FilePath       = $curPath
                        FileSizeMB     = $sizeMB
                        FileFormat     = if ($vhd.VhdFormat) { $vhd.VhdFormat.ToString() } else { 'Unknown' }
                        ParentPath     = if ($vhd.ParentPath) { $vhd.ParentPath } else { '' }
                        CreatedOn      = $created
                        IsBaseDisk     = (-not $vhd.ParentPath)
                        Error          = ''
                    })

                    if (-not $vhd.ParentPath) {
                        $keepGoing = $false
                    }
                    else {
                        $curPath = $vhd.ParentPath
                        $level++
                    }
                }

                # Stamp ChainDepth and ChainTotalMB on every link in this disk's chain
                $depth = $chain.Count
                $totalMB = 0
                foreach ($lnk in $chain) { $totalMB += $lnk.FileSizeMB }
                foreach ($lnk in $chain) {
                    $lnk['ChainDepth']   = $depth
                    $lnk['ChainTotalMB'] = [math]::Round($totalMB, 2)
                    $links.Add($lnk)
                }
            }
        }
        return $links
    }

    foreach ($hostObj in $CompletedHosts) {
        if ($hostObj.Error) { continue }
        $hostName = $hostObj.HostName
        $hostFQDN = if ($hostObj.FQDN)   { $hostObj.FQDN } else { $hostName }
        $cluster  = if ($hostObj.Cluster) { $hostObj.Cluster } else { '' }

        $vmNames = @()
        if ($hostObj.VMs) {
            $vmNames = @($hostObj.VMs | ForEach-Object {
                if ($_.VM) { $_.VM } elseif ($_.VMName) { $_.VMName }
            } | Where-Object { $_ })
        }
        if ($vmNames.Count -eq 0) { continue }

        # Resolve credential for this host's domain
        $hostCred = $Credential
        $hostDomain = if ($hostFQDN -match '\.(.+)$') { $matches[1].ToLower() } else { '' }
        if ($hostDomain -and $DomainCredentials.ContainsKey($hostDomain)) {
            $hostCred = $DomainCredentials[$hostDomain]
        }

        $rawLinks = $null
        try {
            $icArgs = @{
                ComputerName  = $hostFQDN
                ScriptBlock   = $sb
                ArgumentList  = (,$vmNames)
                ErrorAction   = 'Stop'
            }
            if ($hostCred) { $icArgs['Credential'] = $hostCred }
            $rawLinks = Invoke-Command @icArgs
        }
        catch {
            Write-HVLog "  VHD-Chain: collection failed on $hostName -- $($_.Exception.Message)" -Level Warning
            continue
        }

        if (-not $rawLinks) { continue }

        # Apply alerting and recommendation locally (config values don't cross remoting)
        foreach ($lnk in $rawLinks) {
            $depth   = [int]$lnk.ChainDepth
            $created = $lnk.CreatedOn
            $ltype   = $lnk.LinkType

            # AlertLevel for this individual link
            $alertLevel = 'OK'
            if ($ltype -eq 'BrokenParent' -or $ltype -eq 'Error') {
                $alertLevel = 'Critical'
            }
            elseif ($depth -ge $critDepth) {
                $alertLevel = 'Critical'
            }
            elseif ($ltype -eq 'Checkpoint' -and $created -and ((Get-Date) - $created).Days -gt 30) {
                $alertLevel = 'Critical'   # checkpoint > 30 days
            }
            elseif ($depth -ge $warnDepth) {
                $alertLevel = 'Warning'
            }
            elseif ($ltype -eq 'Checkpoint' -and $created -and ((Get-Date) - $created).Days -gt $staleDays) {
                $alertLevel = 'Warning'
            }

            # Recommendation -- only populated on ChainLevel 0 (top/active disk)
            # Other rows get blank to avoid duplication in the worksheet
            $recommendation = ''
            if ($lnk.ChainLevel -eq 0) {
                $recommendation = Get-VHDChainRecommendation `
                    -LinkType  $ltype `
                    -ChainDepth $depth `
                    -VMName    $lnk.VMName `
                    -HostName  $hostName `
                    -ChainLinks @($rawLinks | Where-Object { $_.VMName -eq $lnk.VMName -and
                                                              $_.ControllerNum -eq $lnk.ControllerNum -and
                                                              $_.ControllerLoc -eq $lnk.ControllerLoc }) `
                    -WarnDepth $warnDepth `
                    -CritDepth $critDepth `
                    -StaleDays $staleDays
            }

            $allResults.Add([PSCustomObject]@{
                VMName         = $lnk.VMName
                Host           = $hostName
                ClusterName    = $cluster
                ControllerType = $lnk.ControllerType
                ControllerNum  = $lnk.ControllerNum
                ControllerLoc  = $lnk.ControllerLoc
                ChainLevel     = $lnk.ChainLevel
                LinkType       = $lnk.LinkType
                FilePath       = $lnk.FilePath
                FileSizeMB     = $lnk.FileSizeMB
                FileFormat     = $lnk.FileFormat
                ParentPath     = $lnk.ParentPath
                CreatedOn      = $lnk.CreatedOn
                IsBaseDisk     = $lnk.IsBaseDisk
                ChainDepth     = $lnk.ChainDepth
                ChainTotalMB   = $lnk.ChainTotalMB
                AlertLevel     = $alertLevel
                Recommendation = $recommendation
                Error          = $lnk.Error
                DataSource     = 'HYPER-V'
            })
        }
    }

    return $allResults
}


function Get-VHDChainRecommendation {
    <#
    .SYNOPSIS
        Generates a per-disk consolidation recommendation string based on chain state.
        Called internally by Invoke-VHDChainCollection for ChainLevel = 0 rows only.
    #>
    [CmdletBinding()]
    param(
        [string]$LinkType,
        [int]$ChainDepth,
        [string]$VMName,
        [string]$HostName,
        [array]$ChainLinks,   # All links for this disk (to inspect Checkpoint ages)
        [int]$WarnDepth = 3,
        [int]$CritDepth = 5,
        [int]$StaleDays = 7
    )

    # Find oldest checkpoint link age in this chain
    $checkpointLinks = @($ChainLinks | Where-Object { $_.LinkType -eq 'Checkpoint' -and $_.CreatedOn })
    $oldestCPDays = 0
    if ($checkpointLinks.Count -gt 0) {
        $oldestCPDays = ($checkpointLinks | ForEach-Object {
            ((Get-Date) - [datetime]$_.CreatedOn).Days
        } | Measure-Object -Maximum).Maximum
    }

    $hasBroken = ($ChainLinks | Where-Object { $_.LinkType -eq 'BrokenParent' -or $_.LinkType -eq 'Error' }).Count -gt 0

    if ($hasBroken) {
        $brokenPath = ($ChainLinks | Where-Object { $_.LinkType -eq 'BrokenParent' -or $_.LinkType -eq 'Error' } | Select-Object -First 1).FilePath
        return ("CRITICAL: Chain is broken. Do NOT attempt auto-merge. Contact storage team. " +
                "Broken path: $brokenPath. Restore from backup or reattach the parent VHDX manually.")
    }

    if ($ChainDepth -eq 1) {
        return "Healthy. Single-file disk, no checkpoints. No action needed."
    }

    if ($ChainDepth -eq 2) {
        return ("Normal: 1 checkpoint layer. Typically a linked clone or single active checkpoint. " +
                "If unexpected: Get-VMSnapshot -VMName '$VMName' -ComputerName $HostName | Remove-VMSnapshot")
    }

    # Recent backup in progress (chain 3-4 deep, newest CP created within last 24h)
    $newestCPDays = 999
    if ($checkpointLinks.Count -gt 0) {
        $newestCPDays = ($checkpointLinks | ForEach-Object {
            ((Get-Date) - [datetime]$_.CreatedOn).Days
        } | Measure-Object -Minimum).Minimum
    }
    if ($ChainDepth -in 3..4 -and $newestCPDays -lt 1) {
        return ("In-progress backup chain ($ChainDepth levels). Likely a backup job currently running. " +
                "Re-check in 1-2 hours. If chain persists longer than your backup window, backup may have failed to merge.")
    }

    if ($ChainDepth -ge $CritDepth -or $oldestCPDays -gt 7) {
        return ("STUCK backup chain. $ChainDepth levels, oldest checkpoint $oldestCPDays days old. " +
                "Remediation: " +
                "(1) Pause backups for this VM at the backup server. " +
                "(2) Get-VMSnapshot -VMName '$VMName' -ComputerName $HostName | Remove-VMSnapshot -IncludeAllChildSnapshots. " +
                "(3) Monitor merge via VMMS Event 19070 (start) and 19080 (complete) on $HostName. " +
                "(4) Allow several hours for large chains -- merge is I/O-intensive. " +
                "(5) Verify chain is 1-2 levels after merge before re-enabling backups. " +
                "A per-VM repair script has been generated if EnableRemediationScripts = `$true in config.")
    }

    if ($ChainDepth -ge $WarnDepth) {
        return ("Chain depth elevated: $ChainDepth levels (oldest CP: $oldestCPDays days). Monitor for growth. " +
                "If persistent across report runs, consider manual consolidation: " +
                "Get-VMSnapshot -VMName '$VMName' -ComputerName $HostName | " +
                "Where-Object CreationTime -lt (Get-Date).AddDays(-$StaleDays) | Remove-VMSnapshot")
    }

    return "Chain depth $ChainDepth -- monitoring recommended."
}


Export-ModuleMember -Function @(
    'Invoke-VHDChainCollection'
    'Get-VHDChainRecommendation'
)
