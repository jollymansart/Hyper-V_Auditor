function Merge-HistoryFiles
{
    <#
    .SYNOPSIS
        Merge-HistoryFiles -OldFolder "\\rictx-script-p2\LOG\1\Hyper-V" -NewFolder "\\rictx-script-p2\LOG\Hyper-V" -BackupFirst
        Merges accidentally-separated HyperV Report history JSON files back into single
        unified files without losing any data from either copy.

    .DESCRIPTION
        Merges three file pairs:

        VM-History.json
          - Keyed by VMID. For VMs in both files: earliest FirstSeen, latest LastSeen,
            union of Hosts lists. VMs only in one file are added as-is.

        GuestStorage-History.json
          - Keyed by VMID. For VMs in both files: per drive, all date entries are merged
            and deduplicated by Date (keeping the entry with the most recent CollectedAt
            if a date appears in both files). New drive letters found only in one file
            are added. VMs only in one file are added as-is.

        ResourceMetering-History.json
          - Contains timestamped snapshots. Extracts all snapshots from both files,
            deduplicates by Timestamp, sorts chronologically oldest-first, and
            rebuilds in the nested format the report expects.

    .PARAMETER OldFolder
        Folder containing the files that were moved (the older/recovered copies).
        Can be the same folder if files are named differently.

    .PARAMETER NewFolder
        Folder containing the newly-created files (generated after the move).

    .PARAMETER OutputFolder
        Where to write the merged output files. Defaults to NewFolder.
        IMPORTANT: Do NOT set this to the same folder as NewFolder without first
        backing up the new files -- the output files will overwrite them.

    .PARAMETER BackupFirst
        Back up both input folders before writing output. Default $true.

    .EXAMPLE
        # Old files in C:\Recovered, new files in \\server\logs\Hyper-V
        .\Merge-HistoryFiles.ps1 `
            -OldFolder "C:\Recovered" `
            -NewFolder "\\rictx-script-p2\log\Hyper-V" `
            -OutputFolder "\\rictx-script-p2\log\Hyper-V"

    .EXAMPLE
        # Dry run -- see counts without writing anything
        .\Merge-HistoryFiles.ps1 `
            -OldFolder "C:\Recovered" `
            -NewFolder "\\rictx-script-p2\log\Hyper-V" `
            -WhatIf

    .NOTES
        PowerShell 5.1+. No external modules required.
        Run this ONCE -- the output files can be used as-is by the HyperV Report.
        After merging, delete the old/recovered copies to avoid confusion.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]  [string]$OldFolder,
        [Parameter(Mandatory=$true)]  [string]$NewFolder,
        [Parameter(Mandatory=$false)] [string]$OutputFolder = '',
        [switch]$BackupFirst
    )

    Set-StrictMode -Off
    $ErrorActionPreference = 'Stop'

    if (-not $OutputFolder) { $OutputFolder = $NewFolder }

    # -- Helpers ------------------------------------------------------------------

    function Write-Step { param([string]$Msg, [string]$Color='Cyan')
        Write-Host "`n$Msg" -ForegroundColor $Color }

    function Write-Info  { param([string]$Msg) Write-Host "  $Msg" -ForegroundColor Gray }
    function Write-OK    { param([string]$Msg) Write-Host "  OK  $Msg" -ForegroundColor Green }
    function Write-Warn  { param([string]$Msg) Write-Host "  WARN $Msg" -ForegroundColor Yellow }

    function Load-Json {
        param([string]$Path)
        if (-not (Test-Path $Path)) {
            Write-Warn "File not found: $Path"
            return $null
        }
        try {
            $raw = Get-Content -Path $Path -Raw -Encoding UTF8
            return $raw | ConvertFrom-Json
        }
        catch {
            throw "Failed to parse JSON from $Path -- $($_.Exception.Message)"
        }
    }

    function Save-Json {
        param([string]$Path, [object]$Data)
        if ($WhatIfPreference) {
            Write-Info "[WhatIf] Would write $Path"
            return
        }
        if ($PSCmdlet.ShouldProcess($Path, "Write merged JSON")) {
            $json = $Data | ConvertTo-Json -Depth 20
            [System.IO.File]::WriteAllText($Path, $json, [System.Text.Encoding]::UTF8)
            $kb = [math]::Round((Get-Item $Path).Length / 1KB, 0)
            Write-OK "Written: $Path ($kb KB)"
        }
    }

    function Backup-File {
        param([string]$Path)
        if (Test-Path $Path) {
            $bak = "$Path.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            Copy-Item -Path $Path -Destination $bak -Force
            Write-Info "Backed up: $bak"
        }
    }

    # -- Locate file pairs ---------------------------------------------------------

    Write-Step "===== HyperV Report History File Merger =====" 'White'
    Write-Info "OldFolder:    $OldFolder"
    Write-Info "NewFolder:    $NewFolder"
    Write-Info "OutputFolder: $OutputFolder"

    $filePairs = @(
        @{ Name='VM-History.json';               Type='VMHistory'           }
        @{ Name='GuestStorage-History.json';     Type='GuestStorage'        }
        @{ Name='ResourceMetering-History.json'; Type='ResourceMetering'    }
    )

    foreach ($pair in $filePairs) {
        $pair['OldPath'] = Join-Path $OldFolder $pair.Name
        $pair['NewPath'] = Join-Path $NewFolder $pair.Name
        $pair['OutPath'] = Join-Path $OutputFolder $pair.Name

        $oldExists = Test-Path $pair.OldPath
        $newExists = Test-Path $pair.NewPath
        Write-Info "$($pair.Name): Old=$(if($oldExists){'Found'}else{'MISSING'})  New=$(if($newExists){'Found'}else{'MISSING'})"
    }

    if ($BackupFirst) {
        Write-Step "--- Backing up existing files ---"
        foreach ($pair in $filePairs) {
            Backup-File $pair.NewPath
            if ($pair.OldPath -ne $pair.NewPath) { Backup-File $pair.OldPath }
        }
    }

    # -- MERGE 1: VM-History.json --------------------------------------------------

    Write-Step "--- Merging VM-History.json ---"

    $vmPair  = $filePairs | Where-Object { $_.Type -eq 'VMHistory' }
    $vmOld   = Load-Json $vmPair.OldPath
    $vmNew   = Load-Json $vmPair.NewPath

    if ($vmOld -and $vmNew) {
        # Convert PSCustomObjects to hashtable for clean manipulation
        $merged = @{}

        # Add all entries from OLD
        foreach ($prop in $vmOld.PSObject.Properties) {
            $key   = $prop.Name
            $entry = $prop.Value
            $merged[$key] = @{
                VMName    = $entry.VMName
                VMId      = $entry.VMId
                FirstSeen = $entry.FirstSeen
                LastSeen  = $entry.LastSeen
                Hosts     = @($entry.Hosts)
            }
        }

        # Merge or add all entries from NEW
        $onlyNew = 0; $both = 0; $onlyOld = ($merged.Count)
        foreach ($prop in $vmNew.PSObject.Properties) {
            $key   = $prop.Name
            $entry = $prop.Value

            if ($merged.ContainsKey($key)) {
                # VM in both files -- take earliest FirstSeen, latest LastSeen, union Hosts
                $existing = $merged[$key]
                $both++

                # Compare dates (stored as YYYY-MM-DD strings -- sorts lexicographically)
                if ($entry.FirstSeen -lt $existing.FirstSeen) {
                    $existing.FirstSeen = $entry.FirstSeen
                }
                if ($entry.LastSeen -gt $existing.LastSeen) {
                    $existing.LastSeen = $entry.LastSeen
                }
                # Union Hosts (deduplicated, case-insensitive)
                $hostSet = [System.Collections.Generic.HashSet[string]]::new(
                    [System.StringComparer]::OrdinalIgnoreCase)
                foreach ($h in $existing.Hosts) { [void]$hostSet.Add($h) }
                foreach ($h in @($entry.Hosts)) { [void]$hostSet.Add($h) }
                $existing.Hosts = @($hostSet | Sort-Object)
            }
            else {
                # VM only in NEW
                $merged[$key] = @{
                    VMName    = $entry.VMName
                    VMId      = $entry.VMId
                    FirstSeen = $entry.FirstSeen
                    LastSeen  = $entry.LastSeen
                    Hosts     = @($entry.Hosts)
                }
                $onlyNew++
            }
        }

        $onlyOld = $merged.Count - $both - $onlyNew
        Write-Info "Old-only VMs (recovered):  $onlyOld"
        Write-Info "New-only VMs:              $onlyNew"
        Write-Info "In both (merged):          $both"
        Write-Info "Total merged output:       $($merged.Count)"

        # Convert back to ordered PSObject for consistent JSON output
        $vmOut = [PSCustomObject]@{}
        foreach ($key in ($merged.Keys | Sort-Object)) {
            $vmOut | Add-Member -NotePropertyName $key -NotePropertyValue ([PSCustomObject]$merged[$key])
        }
        Save-Json -Path $vmPair.OutPath -Data $vmOut
    }
    elseif ($vmOld) {
        Write-Warn "No new VM-History.json found -- copying old as output"
        if (-not $WhatIfPreference) { Copy-Item $vmPair.OldPath $vmPair.OutPath -Force }
    }
    elseif ($vmNew) {
        Write-Warn "No old VM-History.json found -- nothing to merge"
    }

    # -- MERGE 2: GuestStorage-History.json ---------------------------------------

    Write-Step "--- Merging GuestStorage-History.json ---"

    $gsPair  = $filePairs | Where-Object { $_.Type -eq 'GuestStorage' }
    $gsOld   = Load-Json $gsPair.OldPath
    $gsNew   = Load-Json $gsPair.NewPath

    if ($gsOld -and $gsNew) {
        $merged = @{}

        # Load all OLD entries
        foreach ($prop in $gsOld.PSObject.Properties) {
            $key   = $prop.Name
            $entry = $prop.Value
            $drives = @{}
            foreach ($dp in $entry.Drives.PSObject.Properties) {
                $drives[$dp.Name] = [System.Collections.Generic.List[object]]::new()
                foreach ($de in $dp.Value) { $drives[$dp.Name].Add($de) }
            }
            $merged[$key] = @{
                VMName = $entry.VMName
                VMId   = $entry.VMId
                Drives = $drives
            }
        }

        $onlyNew = 0; $both = 0
        foreach ($prop in $gsNew.PSObject.Properties) {
            $key   = $prop.Name
            $entry = $prop.Value

            if ($merged.ContainsKey($key)) {
                $both++
                $existing = $merged[$key]

                # Merge each drive
                foreach ($dp in $entry.Drives.PSObject.Properties) {
                    $driveLetter = $dp.Name
                    $newEntries  = $dp.Value

                    if (-not $existing.Drives.ContainsKey($driveLetter)) {
                        # Drive only in new file -- add it
                        $existing.Drives[$driveLetter] = [System.Collections.Generic.List[object]]::new()
                    }

                    # Build a date->entry map from existing entries
                    $dateMap = @{}
                    foreach ($de in $existing.Drives[$driveLetter]) {
                        $dateMap[$de.Date] = $de
                    }

                    # Merge new entries -- add if date not seen; if duplicate date,
                    # keep the one with the most recent CollectedAt
                    foreach ($ne in $newEntries) {
                        $d = $ne.Date
                        if (-not $dateMap.ContainsKey($d)) {
                            $dateMap[$d] = $ne
                        }
                        else {
                            # Both have same date -- keep most recently collected
                            $existCa = $dateMap[$d].CollectedAt
                            $newCa   = $ne.CollectedAt
                            if ($newCa -gt $existCa) { $dateMap[$d] = $ne }
                        }
                    }

                    # Rebuild drive list sorted by Date ascending
                    $existing.Drives[$driveLetter] = [System.Collections.Generic.List[object]]::new()
                    foreach ($d in ($dateMap.Keys | Sort-Object)) {
                        $existing.Drives[$driveLetter].Add($dateMap[$d])
                    }
                }
            }
            else {
                # VM only in new file
                $drives = @{}
                foreach ($dp in $entry.Drives.PSObject.Properties) {
                    $drives[$dp.Name] = [System.Collections.Generic.List[object]]::new()
                    foreach ($de in $dp.Value) { $drives[$dp.Name].Add($de) }
                }
                $merged[$key] = @{
                    VMName = $entry.VMName
                    VMId   = $entry.VMId
                    Drives = $drives
                }
                $onlyNew++
            }
        }

        $onlyOld = $merged.Count - $both - $onlyNew
        Write-Info "Old-only VMs (recovered):  $onlyOld"
        Write-Info "New-only VMs:              $onlyNew"
        Write-Info "In both (drives merged):   $both"
        Write-Info "Total merged output:       $($merged.Count)"

        # Count total drive data points
        $totalPoints = 0
        foreach ($vm in $merged.Values) {
            foreach ($drive in $vm.Drives.Values) { $totalPoints += $drive.Count }
        }
        Write-Info "Total drive data points:   $totalPoints"

        # Build output PSObject
        $gsOut = [PSCustomObject]@{}
        foreach ($key in ($merged.Keys | Sort-Object)) {
            $vm = $merged[$key]
            # Convert Drives hashtable back to PSObject
            $drivesOut = [PSCustomObject]@{}
            foreach ($dl in ($vm.Drives.Keys | Sort-Object)) {
                $drivesOut | Add-Member -NotePropertyName $dl -NotePropertyValue @($vm.Drives[$dl])
            }
            $vmOut = [PSCustomObject]@{
                VMName = $vm.VMName
                VMId   = $vm.VMId
                Drives = $drivesOut
            }
            $gsOut | Add-Member -NotePropertyName $key -NotePropertyValue $vmOut
        }
        Save-Json -Path $gsPair.OutPath -Data $gsOut
    }
    elseif ($gsOld) {
        Write-Warn "No new GuestStorage-History.json -- copying old as output"
        if (-not $WhatIfPreference) { Copy-Item $gsPair.OldPath $gsPair.OutPath -Force }
    }
    elseif ($gsNew) {
        Write-Warn "No old GuestStorage-History.json -- nothing to merge"
    }

    # -- MERGE 3: ResourceMetering-History.json ------------------------------------

    Write-Step "--- Merging ResourceMetering-History.json ---"

    $rmPair = $filePairs | Where-Object { $_.Type -eq 'ResourceMetering' }
    $rmOld  = Load-Json $rmPair.OldPath
    $rmNew  = Load-Json $rmPair.NewPath

    function Extract-RMSnapshots {
        param([object]$Obj, [System.Collections.Generic.List[object]]$Snaps = $null)
        if ($null -eq $Snaps) { $Snaps = [System.Collections.Generic.List[object]]::new() }
        if ($Obj -is [System.Object[]]) {
            foreach ($item in $Obj) { Extract-RMSnapshots -Obj $item -Snaps $Snaps }
        }
        elseif ($null -ne $Obj -and $Obj.PSObject.Properties.Name -contains 'Timestamp') {
            [void]$Snaps.Add($Obj)
        }
        elseif ($null -ne $Obj -and $Obj.PSObject.Properties.Name -contains 'value') {
            Extract-RMSnapshots -Obj $Obj.value -Snaps $Snaps
        }
        elseif ($null -ne $Obj -and $Obj.PSObject.Properties.Name -contains 'Count') {
            # Skip wrapper objects
        }
        return $Snaps
    }

    if ($rmOld -and $rmNew) {
        $snapsOld = Extract-RMSnapshots -Obj $rmOld
        $snapsNew = Extract-RMSnapshots -Obj $rmNew

        Write-Info "Old snapshots found: $($snapsOld.Count)"
        foreach ($s in $snapsOld) { Write-Info "  $($s.Timestamp) -- VMs: $(@($s.VMSummary).Count)" }
        Write-Info "New snapshots found: $($snapsNew.Count)"
        foreach ($s in $snapsNew) { Write-Info "  $($s.Timestamp) -- VMs: $(@($s.VMSummary).Count)" }

        # Deduplicate by Timestamp then sort chronologically
        $snapMap = [ordered]@{}
        foreach ($s in $snapsOld) { $snapMap[$s.Timestamp] = $s }
        foreach ($s in $snapsNew) {
            if (-not $snapMap.Contains($s.Timestamp)) {
                $snapMap[$s.Timestamp] = $s
            }
            else {
                # Same timestamp -- keep the one with more VM entries
                $existCount = @($snapMap[$s.Timestamp].VMSummary).Count
                $newCount   = @($s.VMSummary).Count
                if ($newCount -gt $existCount) { $snapMap[$s.Timestamp] = $s }
            }
        }

        # Sort by timestamp and output as flat array (the report reader handles all nesting formats)
        $mergedSnaps = @($snapMap.Keys | Sort-Object | ForEach-Object { $snapMap[$_] })

        Write-Info "Merged snapshot count:    $($mergedSnaps.Count)"
        foreach ($s in $mergedSnaps) {
            Write-Info "  $($s.Timestamp) -- VMs: $(@($s.VMSummary).Count) Hosts: $(@($s.HostSummary).Count)"
        }

        # Output as simple JSON array -- cleaner than the nested wrapper structure
        Save-Json -Path $rmPair.OutPath -Data $mergedSnaps
    }
    elseif ($rmOld) {
        Write-Warn "No new ResourceMetering-History.json -- extracting and saving clean format from old"
        $snaps = Extract-RMSnapshots -Obj $rmOld
        Write-Info "Snapshots extracted: $($snaps.Count)"
        Save-Json -Path $rmPair.OutPath -Data @($snaps)
    }
    elseif ($rmNew) {
        Write-Warn "No old ResourceMetering-History.json -- nothing to merge"
    }

    # -- Summary -------------------------------------------------------------------

    Write-Step "===== Merge Complete =====" 'White'
    Write-Info "Output files written to: $OutputFolder"
    Write-Info ""
    Write-Info "Next steps:"
    Write-Info "  1. Verify the merged files look correct (check file sizes -- should be larger than either input)"
    Write-Info "  2. Keep the old/recovered copies until after the next successful report run confirms data integrity"
    Write-Info "  3. Run the HyperV Report -- it will read the merged history files automatically"
    Write-Info "  4. Delete the old/recovered copies after confirming the run succeeds"

}