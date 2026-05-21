<#
.SYNOPSIS
    Get-NimbleStorageInventory.ps1
    Comprehensive HPE Nimble Storage inventory and performance collection.

.DESCRIPTION
    Dot-source this file, then call the function:
      . .\Get-NimbleStorageInventory.ps1
      Get-NimbleStorageInventory -ArrayIP '10.91.1.174' -Credential (Get-Credential)

    Supports TWO collection methods (tests both by default):
      1. HPE Nimble PowerShell Toolkit (Get-NS* cmdlets) -- PS7 + module
      2. Direct REST API (port 5392) -- PS 5.1 and PS 7

    OUTPUT: Excel workbook (14 tabs) + JSON per method.

.NOTES
    Author: Michael George | Version: 1.2.0 | Date: 2026-03-22 | PS: 5.1+
    NimbleOS: 6.1.2+ (tested). REST API requires port 5392 HTTPS access.
#>

function Get-NimbleStorageInventory {
    <#
    .SYNOPSIS
        Collects comprehensive HPE Nimble Storage inventory and performance data.
    .PARAMETER ArrayIP
        Management IP of the Nimble array. Default: 10.91.1.174
    .PARAMETER Credential
        PSCredential. Loads from CredentialPath or prompts if not provided.
    .PARAMETER CredentialPath
        Path to Export-Clixml credential. Default: C:\ProgramData\S\nimble-cred.xml
    .PARAMETER OutputPath
        Output directory. Default: current directory.
    .PARAMETER ArrayName
        Friendly name. Default: auto-detected from array.
    .PARAMETER CollectionMode
        Both (test both), Toolkit (Get-NS* only), REST (API only).
    .PARAMETER IncludeSnapshots
        Collect snapshot detail. Default: $true.
    .PARAMETER HyperVClusterName
        Cluster name for LUN mapping. Default: RICTX-UCS-CLS.
    .EXAMPLE
        Get-NimbleStorageInventory -ArrayIP '10.91.1.174' -Credential (Get-Credential)
    .EXAMPLE
        Get-NimbleStorageInventory -ArrayIP '10.91.1.174' -CollectionMode REST
    .EXAMPLE
        $cred = Get-Credential; Get-NimbleStorageInventory -ArrayIP '10.91.1.174' -Credential $cred -CollectionMode Toolkit
    #>
    [CmdletBinding()]
    param(
        [string]$ArrayIP = '10.91.1.174',
        [System.Management.Automation.PSCredential]$Credential,
        [string]$CredentialPath = 'C:\ProgramData\S\nimble-cred.xml',
        [string]$OutputPath = (Get-Location).Path,
        [string]$ArrayName = '',
        [ValidateSet('Both','Toolkit','REST')][string]$CollectionMode = 'Both',
        [bool]$IncludeSnapshots = $true,
        [string]$HyperVClusterName = 'RICTX-UCS-CLS'
    )

    $ErrorActionPreference = 'Stop'
    $scriptVersion = '1.2.0'
    $ts     = Get-Date
    $tsStr  = $ts.ToString('yyyy-MM-dd HH:mm:ss')
    $fileTS = $ts.ToString('yyyyMMdd_HHmmss')

    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  HPE Nimble Storage Inventory -- $tsStr" -ForegroundColor Cyan
    Write-Host "  Array: $ArrayIP | Mode: $CollectionMode | v$scriptVersion" -ForegroundColor Cyan
    Write-Host "  PowerShell: $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)" -ForegroundColor Cyan
    Write-Host "================================================================`n" -ForegroundColor Cyan

    # --- SSL bypass ---
    $isPS7 = ($PSVersionTable.PSVersion.Major -ge 7)
    if (-not $isPS7) {
        if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
            Add-Type 'using System.Net; using System.Security.Cryptography.X509Certificates; public class TrustAllCertsPolicy : ICertificatePolicy { public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; } }'
        }
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    }

    # --- Credential ---
    if (-not $Credential -and $CredentialPath -and (Test-Path $CredentialPath)) {
        try { $Credential = Import-Clixml $CredentialPath; Write-Host "[Auth] Loaded from $CredentialPath" -ForegroundColor Cyan } catch { Write-Warning "Cred load: $($_.Exception.Message)" }
    }
    if (-not $Credential) { $Credential = Get-Credential -Message "Nimble Array ($ArrayIP)" }
    if (-not $Credential) { Write-Error "No credential."; return }

    # === REST API internals ===
    $nimbleBase = "https://${ArrayIP}:5392/v1"
    $nimbleToken = $null; $nimbleHdr = $null

    function _REST_Connect {
        $body = @{data=@{username=$Credential.UserName;password=$Credential.GetNetworkCredential().Password}} | ConvertTo-Json -Depth 3
        $irm = @{ Uri="$nimbleBase/tokens"; Method='Post'; Body=$body; ContentType='application/json'; ErrorAction='Stop' }
        if ($isPS7) { $irm['SkipCertificateCheck']=$true }
        try {
            $r = Invoke-RestMethod @irm
            Set-Variable -Name nimbleToken -Value $r.data.session_token -Scope 1
            Set-Variable -Name nimbleHdr -Value @{'X-Auth-Token'=$r.data.session_token} -Scope 1
            if (-not $r.data.session_token) { throw "No token" }
            return $true
        } catch { Write-Warning "REST connect: $($_.Exception.Message)"; return $false }
    }

    function _REST_Get {
        param([string]$Endpoint, [switch]$Detail)
        $url = "$nimbleBase/$Endpoint"
        $all = @(); $pg = $url
        do {
            $irm = @{ Uri=$pg; Method='Get'; Headers=$nimbleHdr; ContentType='application/json'; ErrorAction='Stop' }
            if ($isPS7) { $irm['SkipCertificateCheck']=$true }
            try {
                $r = Invoke-RestMethod @irm
                if ($r.data) { $all += $r.data }
                $pg = $null
                if ($r.endRow -and $r.totalRows -and $r.endRow -lt ($r.totalRows - 1)) {
                    $sep = if ($url -match '\?') { '&' } else { '?' }
                    $pg = "${url}${sep}startRow=$($r.endRow + 1)"
                }
            } catch { Write-Warning "API $Endpoint : $($_.Exception.Message)"; $pg = $null }
        } while ($pg)
        # NimbleOS 6.x: list may return summary only. If Detail requested and few props, fetch each by ID.
        if ($Detail -and $all.Count -gt 0) {
            $propCount = @($all[0].PSObject.Properties).Count
            if ($propCount -le 5 -and $all[0].id) {
                $baseEp = ($Endpoint -split '\?')[0]
                $detailed = @()
                foreach ($item in $all) {
                    $iUrl = "$nimbleBase/${baseEp}/$($item.id)"
                    $iIrm = @{ Uri=$iUrl; Method='Get'; Headers=$nimbleHdr; ContentType='application/json'; ErrorAction='SilentlyContinue' }
                    if ($isPS7) { $iIrm['SkipCertificateCheck']=$true }
                    try { $ir = Invoke-RestMethod @iIrm; if ($ir.data) { $detailed += $ir.data } } catch {}
                }
                if ($detailed.Count -gt 0) { $all = $detailed }
            }
        }
        return $all
    }

    function _REST_Disconnect {
        if ($nimbleToken) {
            $irm = @{ Uri="$nimbleBase/tokens/$nimbleToken"; Method='Delete'; Headers=$nimbleHdr; ContentType='application/json'; ErrorAction='SilentlyContinue' }
            if ($isPS7) { $irm['SkipCertificateCheck']=$true }
            try { Invoke-RestMethod @irm | Out-Null } catch {}
        }
    }

    # === Utility ===
    function _Epoch { param($E); if (!$E -or $E -eq 0) { return '' }; try { [DateTimeOffset]::FromUnixTimeSeconds($E).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss') } catch { '' } }
    function _GB { param($B); if (!$B -or $B -eq 0) { return 0 }; [math]::Round($B / 1GB, 2) }
    function _TB { param($B); if (!$B -or $B -eq 0) { return 0 }; [math]::Round($B / 1TB, 2) }
    function _S { param($V, $D = ''); if ($null -ne $V) { $V } else { $D } }

    # === COLLECT VIA TOOLKIT ===
    function _Collect_Toolkit {
        Write-Host "=== TOOLKIT COLLECTION (Get-NS*) ===" -ForegroundColor Magenta
        $sw = [System.Diagnostics.Stopwatch]::StartNew(); $r = @{}
        try {
            Connect-NSGroup -Group $ArrayIP -Credential $Credential -ImportServerCertificate -ErrorAction Stop
            Write-Host "  [OK] Connected via Connect-NSGroup" -ForegroundColor Green
        } catch {
            Write-Host "  [FAIL] $($_.Exception.Message)" -ForegroundColor Red
            return @{ Success=$false; Error=$_.Exception.Message; Duration=$sw.Elapsed }
        }
        try {
            $eps = @(
                @{K='Arrays';C={Get-NSArray}}, @{K='Groups';C={Get-NSGroup}}, @{K='Controllers';C={Get-NSController}},
                @{K='Shelves';C={Get-NSShelf}}, @{K='Disks';C={Get-NSDisk}}, @{K='Pools';C={Get-NSPool}},
                @{K='Volumes';C={Get-NSVolume}}, @{K='FCInterfaces';C={Get-NSFibreChannelInterface}},
                @{K='FCPorts';C={Get-NSFibreChannelPort}}, @{K='FCSessions';C={Get-NSFibreChannelSession}},
                @{K='InitiatorGroups';C={Get-NSInitiatorGroup}}, @{K='ACRecords';C={Get-NSAccessControlRecord}},
                @{K='Alarms';C={Get-NSAlarm}}, @{K='PerfPolicies';C={Get-NSPerformancePolicy}},
                @{K='Folders';C={Get-NSFolder}}
            )
            if ($IncludeSnapshots) { $eps += @{K='Snapshots';C={
                # NimbleOS 6.x requires vol_id for snapshot queries -- collect per volume
                $allSnaps = @()
                $vols = Get-NSVolume -ErrorAction SilentlyContinue
                foreach ($v in $vols) {
                    try { $allSnaps += @(Get-NSSnapshot -vol_id $v.id -ErrorAction SilentlyContinue) } catch {}
                }
                $allSnaps
            }} }
            foreach ($ep in $eps) {
                Write-Host "  $($ep.K)..." -NoNewline
                try { $r[$ep.K] = @(& $ep.C -ErrorAction SilentlyContinue); Write-Host " $($r[$ep.K].Count)" -ForegroundColor Green }
                catch { $r[$ep.K] = @(); Write-Host " ERR: $($_.Exception.Message)" -ForegroundColor Red }
            }
            $r.Success=$true; $r.Duration=$sw.Elapsed
        } catch { $r.Success=$false; $r.Error=$_.Exception.Message; $r.Duration=$sw.Elapsed }
        finally { try { Disconnect-NSGroup -ErrorAction SilentlyContinue } catch {} }
        $sw.Stop(); Write-Host "  Toolkit: $($sw.Elapsed.TotalSeconds.ToString('F1'))s" -ForegroundColor Cyan
        return $r
    }

    # === COLLECT VIA REST ===
    function _Collect_REST {
        Write-Host "=== REST API COLLECTION (port 5392) ===" -ForegroundColor Magenta
        $sw = [System.Diagnostics.Stopwatch]::StartNew(); $r = @{}
        if (-not (_REST_Connect)) { return @{ Success=$false; Error='REST connect failed'; Duration=$sw.Elapsed } }
        Write-Host "  [OK] Connected via REST token" -ForegroundColor Green
        try {
            $eps = @(
                @{K='Arrays';E='arrays'}, @{K='Groups';E='groups'}, @{K='Controllers';E='controllers'},
                @{K='Shelves';E='shelves'}, @{K='Disks';E='disks'}, @{K='Pools';E='pools'},
                @{K='Volumes';E='volumes'}, @{K='FCInterfaces';E='fibre_channel_interfaces'},
                @{K='FCPorts';E='fibre_channel_ports'}, @{K='FCSessions';E='fibre_channel_sessions'},
                @{K='InitiatorGroups';E='initiator_groups'}, @{K='ACRecords';E='access_control_records'},
                @{K='Alarms';E='alarms'}, @{K='PerfPolicies';E='performance_policies'},
                @{K='Folders';E='folders'}
            )
            if ($IncludeSnapshots) { } # handled after main loop
            foreach ($ep in $eps) {
                Write-Host "  $($ep.K)..." -NoNewline
                try { $r[$ep.K] = @(_REST_Get -Endpoint $ep.E -Detail); Write-Host " $($r[$ep.K].Count)" -ForegroundColor Green }
                catch { $r[$ep.K] = @(); Write-Host " ERR: $($_.Exception.Message)" -ForegroundColor Red }
            }
            # Snapshots: NimbleOS 6.x requires vol_id -- collect per-volume after Volumes are loaded
            if ($IncludeSnapshots -and $r.Volumes -and $r.Volumes.Count -gt 0) {
                Write-Host "  Snapshots..." -NoNewline
                $allSnaps = @()
                foreach ($v in $r.Volumes) {
                    $vid = $v.id
                    if ($vid) { try { $allSnaps += @(_REST_Get -Endpoint "snapshots?vol_id=$vid") } catch {} }
                }
                $r['Snapshots'] = $allSnaps
                Write-Host " $($allSnaps.Count)" -ForegroundColor Green
            }
            $r.Success=$true; $r.Duration=$sw.Elapsed
        } catch { $r.Success=$false; $r.Error=$_.Exception.Message; $r.Duration=$sw.Elapsed }
        finally { _REST_Disconnect }
        $sw.Stop(); Write-Host "  REST: $($sw.Elapsed.TotalSeconds.ToString('F1'))s" -ForegroundColor Cyan
        return $r
    }

    # === NORMALIZE to report rows ===
    function _BuildReport {
        param([hashtable]$Raw, [string]$Src)
        Write-Host "--- Building report ($Src) ---" -ForegroundColor DarkCyan
        $rpt = @{}

        $rpt.ArrayOverview = @($Raw.Arrays | ForEach-Object {
            [PSCustomObject]@{ ArrayName=_S $_.name; Model=_S $_.model; Serial=_S $_.serial; NimbleOS=_S $_.version_current; ExtModel=_S $_.extended_model; RawCapTB=_TB $_.raw_capacity_bytes; UsableCapTB=_TB $_.usable_capacity_bytes; VolUsageTB=_TB $_.vol_usage_bytes; SnapUsageTB=_TB $_.snap_usage_bytes; Status=_S $_.status 'Unknown'; Role=_S $_.role; Created=_Epoch $_.creation_time }
        })
        if ($rpt.ArrayOverview.Count -gt 0 -and -not $script:_detName) { $script:_detName = $rpt.ArrayOverview[0].ArrayName }

        $rpt.GroupSummary = @($Raw.Groups | ForEach-Object {
            [PSCustomObject]@{ GroupName=_S $_.name; Leader=_S $_.leader_array_name; UsableTB=_TB $_.usable_capacity_bytes; FreeTB=_TB $_.free_space; VolUsageTB=_TB $_.usage; SnapTB=_TB $_.snap_usage_bytes; CompRatio=_S $_.compression_ratio 0; DedupeRatio=_S $_.dedupe_ratio 0; SavedTB=_TB $_.savings_bytes; Domain=_S $_.domain_name }
        })

        $rpt.Controllers = @($Raw.Controllers | ForEach-Object {
            [PSCustomObject]@{ Name=_S $_.name; Array=_S $_.array_name_or_serial; State=_S $_.state 'Unknown'; Serial=_S $_.serial; Model=_S $_.model; Hostname=_S $_.hostname; Partner=_S $_.partner_name; PartnerState=_S $_.partner_state; IsMaster=if((_S $_.master_state) -eq 'master'){'Yes'}else{'No'} }
        })

        $rpt.Shelves = @($Raw.Shelves | ForEach-Object {
            [PSCustomObject]@{ Serial=_S $_.serial; Model=_S $_.model; ModelExt=_S $_.model_ext; Array=_S $_.array_name; Location=_S $_.shelf_location; Chassis=_S $_.chassis_type; Disks=_S $_.activated_disk_count 0 }
        })

        $rpt.Disks = @($Raw.Disks | ForEach-Object {
            $st = _S $_.state
            [PSCustomObject]@{ Slot=_S $_.slot ''; ShelfSerial=_S $_.shelf_serial; Type=_S $_.type 'Unknown'; State=$st; SizeGB=_GB $_.size; Model=_S $_.model; Vendor=_S $_.vendor; Serial=_S $_.serial; FW=_S $_.firmware_version; RaidState=_S $_.raid_state; Health=if($st -in @('valid','in use')){'Healthy'}elseif($st -eq 'absent'){'Missing'}else{'Review'} }
        })

        $rpt.Pools = @($Raw.Pools | ForEach-Object {
            $tTB=_TB $_.capacity; $fTB=_TB $_.free_space; $uTB=[math]::Round($tTB-$fTB,2); $pct=if($tTB -gt 0){[math]::Round(($uTB/$tTB)*100,1)}else{0}
            [PSCustomObject]@{ Pool=_S $_.name; TotalTB=$tTB; UsedTB=$uTB; FreeTB=$fTB; UsedPct=$pct; VolUsageTB=_TB $_.vol_space_usage; SnapUsageTB=_TB $_.snap_space_usage; CompRatio=_S $_.savings_ratio 0; CacheGB=_GB $_.cache_capacity; Vols=_S $_.vol_count 0; Snaps=_S $_.snap_count 0; Alert=if($pct -ge 90){'Critical'}elseif($pct -ge 80){'Warning'}elseif($pct -ge 70){'Monitor'}else{'OK'} }
        })

        $rpt.Volumes = @($Raw.Volumes | ForEach-Object {
            $sz=_GB $_.size; $mp=_GB $_.vol_usage_mapped_bytes; $sn=_GB $_.snap_usage_bytes; $pct=if($sz -gt 0){[math]::Round(($mp/$sz)*100,1)}else{0}
            $s=$_.avg_stats_last_5mins
            $ri=_S ($s).read_iops 0; $wi=_S ($s).write_iops 0; $ci=_S ($s).combined_iops 0
            $rl=if($s -and $s.read_latency){[math]::Round($s.read_latency/1000,2)}else{0}
            $wl=if($s -and $s.write_latency){[math]::Round($s.write_latency/1000,2)}else{0}
            $cl=if($s -and $s.combined_latency){[math]::Round($s.combined_latency/1000,2)}else{0}
            $rt=if($s -and $s.read_throughput){[math]::Round($s.read_throughput/1MB,2)}else{0}
            $wt=if($s -and $s.write_throughput){[math]::Round($s.write_throughput/1MB,2)}else{0}
            $ct2=if($s -and $s.combined_throughput){[math]::Round($s.combined_throughput/1MB,2)}else{0}
            [PSCustomObject]@{ Volume=_S $_.name; FullName=_S $_.full_name; Pool=_S $_.pool_name; Folder=_S $_.folder_name; Online=if($_.online){'Yes'}else{'No'}; SizeGB=$sz; MappedGB=$mp; SnapGB=$sn; UsedPct=$pct; RdIOPS=$ri; WrIOPS=$wi; IOPS=$ci; RdLatMs=$rl; WrLatMs=$wl; LatMs=$cl; RdMBs=$rt; WrMBs=$wt; MBs=$ct2; BlockSize=_S $_.block_size ''; CachePolicy=_S $_.cache_policy; Dedupe=_S $_.dedupe_enabled $false; PerfPolicy=_S $_.perfpolicy_name; AppCat=_S $_.app_category; Target=_S $_.target_name; Serial=_S $_.serial_number; Clone=if($_.clone){'Yes'}else{'No'}; VolColl=_S $_.volcoll_name; Protection=_S $_.protection_type; FCConn=_S $_.num_fc_connections 0; Created=_Epoch $_.creation_time; VolId=_S $_.id; Alert=if($pct -ge 90){'Critical'}elseif($pct -ge 80){'Warning'}elseif($pct -ge 70){'Monitor'}else{'OK'} }
        })

        $rpt.VolumeIOPS = @($rpt.Volumes | Where-Object {$_.Online -eq 'Yes'} | Select-Object Volume,Pool,SizeGB,MappedGB,UsedPct,RdIOPS,WrIOPS,IOPS,RdLatMs,WrLatMs,LatMs,RdMBs,WrMBs,MBs,FCConn,PerfPolicy,Alert | Sort-Object IOPS -Descending)

        $rpt.FCInterfaces = @($Raw.FCInterfaces | ForEach-Object {
            [PSCustomObject]@{ Name=_S $_.name; WWPN=_S $_.wwpn; Online=if($_.online){'Yes'}else{'No'}; Speed=_S $_.link_speed; MaxSpeed=_S $_.max_link_speed; Controller=_S $_.controller_name; Array=_S $_.array_name_or_serial; FW=_S $_.firmware_version }
        })

        $rpt.FCSessions = @($Raw.FCSessions | ForEach-Object {
            [PSCustomObject]@{ InitAlias=_S $_.initiator_alias; InitWWPN=_S $_.initiator_wwpn; SwitchName=_S $_.initiator_switch_name; SwitchPort=_S $_.initiator_switch_port; TargetWWPN=_S $_.target_wwpn; TargetArray=_S $_.target_port_array_name }
        })

        $rpt.InitiatorGroups = @($Raw.InitiatorGroups | ForEach-Object {
            $w=@(); if($_.fc_initiators){$w=@($_.fc_initiators|ForEach-Object{_S $_.wwpn})}
            [PSCustomObject]@{ Group=_S $_.name; Desc=_S $_.description; Protocol=_S $_.access_protocol; HostType=_S $_.host_type; Inits=$w.Count; FCWWPNs=$w -join '; '; IGId=_S $_.id }
        })

        $vL=@{}; foreach($v in $rpt.Volumes){if($v.VolId){$vL[$v.VolId]=$v}}
        $iL=@{}; foreach($i in $rpt.InitiatorGroups){if($i.IGId){$iL[$i.IGId]=$i}}
        $rpt.LUNHostMap = @()
        foreach ($acr in $Raw.ACRecords) {
            $vol = $null; $ig = $null
            if ($acr.vol_id -and $vL.ContainsKey($acr.vol_id)) { $vol = $vL[$acr.vol_id] }
            if ($acr.initiator_group_id -and $iL.ContainsKey($acr.initiator_group_id)) { $ig = $iL[$acr.initiator_group_id] }
            $volName  = if ($acr.vol_name) { $acr.vol_name } elseif ($vol) { $vol.Volume } else { '' }
            $igName   = if ($acr.initiator_group_name) { $acr.initiator_group_name } elseif ($ig) { $ig.Group } else { '' }
            $wwpns    = if ($ig) { $ig.FCWWPNs } else { '' }
            $rpt.LUNHostMap += [PSCustomObject]@{
                Volume    = $volName
                LUN       = _S $acr.lun ''
                InitGroup = $igName
                HostWWPNs = $wwpns
                SizeGB    = if ($vol) { $vol.SizeGB }    else { '' }
                MappedGB  = if ($vol) { $vol.MappedGB }  else { '' }
                UsedPct   = if ($vol) { $vol.UsedPct }   else { '' }
                IOPS      = if ($vol) { $vol.IOPS }      else { 0 }
                LatMs     = if ($vol) { $vol.LatMs }     else { 0 }
                MBs       = if ($vol) { $vol.MBs }       else { 0 }
                Protocol  = _S $acr.access_protocol
                HVCluster = $HyperVClusterName
            }
        }

        $rpt.SnapshotSummary = @()
        if ($Raw.Snapshots) {
            $sg = $Raw.Snapshots | Group-Object { _S $_.vol_name (_S $_.vol_id '') }
            foreach ($g in $sg) {
                $tGB=0; foreach($s2 in $g.Group){$tGB+=_GB $s2.snap_usage_bytes}
                $old=$null;$new=$null; foreach($s2 in $g.Group){$c=$s2.creation_time; if($null -ne $c -and ($null -eq $old -or $c -lt $old)){$old=$c}; if($null -ne $c -and ($null -eq $new -or $c -gt $new)){$new=$c}}
                $v=$rpt.Volumes|Where-Object{$_.Volume -eq $g.Name}|Select-Object -First 1
                $vSz  = if ($v) { $v.SizeGB } else { 0 }
                $sPct = if ($v -and $v.SizeGB -gt 0) { [math]::Round(($tGB/$v.SizeGB)*100,1) } else { 0 }
                $rpt.SnapshotSummary += [PSCustomObject]@{ Volume=$g.Name; Count=$g.Group.Count; TotalGB=[math]::Round($tGB,2); Oldest=_Epoch $old; Newest=_Epoch $new; VolSizeGB=$vSz; SnapPct=$sPct }
            }
        }

        $rpt.Alarms = @($Raw.Alarms | ForEach-Object {
            [PSCustomObject]@{ Severity=_S $_.severity; Category=_S $_.category; Activity=_S $_.activity; Object=_S $_.object_name; Ack=_S $_.acknowledge ''; OnsetTime=_Epoch $_.onset_time; Status=_S $_.status }
        })
        return $rpt
    }

    # === EXPORT ===
    function _Export {
        param([hashtable]$Rpt, [string]$Src, [string]$Dir, [string]$Arr, [string]$FTS)
        $base = "NimbleInventory_${Arr}_${Src}_${FTS}"
        $jp = Join-Path $Dir "${base}.json"; $xp = Join-Path $Dir "${base}.xlsx"
        $Rpt | ConvertTo-Json -Depth 5 -Compress | Set-Content $jp -Encoding UTF8
        Write-Host "  JSON: $jp" -ForegroundColor Green
        try {
            if (-not (Get-Module -ListAvailable -Name ImportExcel -ErrorAction SilentlyContinue)) { Write-Warning "ImportExcel not found. Install: Install-Module ImportExcel"; return }
            Import-Module ImportExcel -ErrorAction Stop
            $p = @{ Path=$xp; AutoSize=$true; FreezeTopRow=$true; BoldTopRow=$true; TableStyle='Medium2' }
            $ct = @(New-ConditionalText -Text 'Critical' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'; New-ConditionalText -Text 'Warning' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404')
            $dc = @(New-ConditionalText -Text 'Missing' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'; New-ConditionalText -Text 'Review' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404')
            $ac = @(New-ConditionalText -Text 'critical' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'; New-ConditionalText -Text 'warning' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404')
            if ($Rpt.ArrayOverview.Count -gt 0)   { $Rpt.ArrayOverview  | Export-Excel @p -WorksheetName 'Array-Overview' }
            if ($Rpt.GroupSummary.Count -gt 0)    { $Rpt.GroupSummary   | Export-Excel @p -WorksheetName 'Group-Summary' }
            if ($Rpt.Controllers.Count -gt 0)     { $Rpt.Controllers    | Export-Excel @p -WorksheetName 'Controllers' }
            if ($Rpt.Shelves.Count -gt 0)         { $Rpt.Shelves        | Export-Excel @p -WorksheetName 'Shelves' }
            if ($Rpt.Disks.Count -gt 0)           { $Rpt.Disks | Sort-Object ShelfSerial,Slot | Export-Excel @p -WorksheetName 'Physical-Disks' -ConditionalText $dc }
            if ($Rpt.Pools.Count -gt 0)           { $Rpt.Pools          | Export-Excel @p -WorksheetName 'Pools' -ConditionalText $ct }
            if ($Rpt.Volumes.Count -gt 0)         { $Rpt.Volumes | Sort-Object Pool,Volume | Export-Excel @p -WorksheetName 'Volumes' -ConditionalText $ct }
            if ($Rpt.VolumeIOPS.Count -gt 0)      { $Rpt.VolumeIOPS     | Export-Excel @p -WorksheetName 'Volume-IOPS' }
            if ($Rpt.FCInterfaces.Count -gt 0)    { $Rpt.FCInterfaces   | Export-Excel @p -WorksheetName 'FC-Interfaces' }
            if ($Rpt.FCSessions.Count -gt 0)      { $Rpt.FCSessions     | Export-Excel @p -WorksheetName 'FC-Sessions' }
            if ($Rpt.InitiatorGroups.Count -gt 0) { $Rpt.InitiatorGroups| Export-Excel @p -WorksheetName 'Initiator-Groups' }
            if ($Rpt.LUNHostMap.Count -gt 0)      { $Rpt.LUNHostMap | Sort-Object InitGroup,LUN | Export-Excel @p -WorksheetName 'LUN-Host-Map' }
            if ($Rpt.SnapshotSummary.Count -gt 0) { $Rpt.SnapshotSummary| Sort-Object Volume | Export-Excel @p -WorksheetName 'Snapshot-Summary' }
            if ($Rpt.Alarms.Count -gt 0)          { $Rpt.Alarms | Sort-Object Severity | Export-Excel @p -WorksheetName 'Alarms' -ConditionalText $ac }
            Write-Host "  Excel: $xp" -ForegroundColor Green
        } catch { Write-Warning "Excel: $($_.Exception.Message)" }
    }

    # ============================================================
    # MAIN EXECUTION
    # ============================================================
    $script:_detName = $ArrayName
    $tkR = $null; $reR = $null

    # Toolkit
    if ($CollectionMode -in @('Both','Toolkit')) {
        $tkAvail = $false
        $tkM = Get-Module -ListAvailable -Name 'HPENimblePowerShellToolkit' -ErrorAction SilentlyContinue
        if (-not $tkM) { $tkM = Get-Module -ListAvailable -Name 'HPEAlletra6000andNimbleStoragePowerShellToolkit' -ErrorAction SilentlyContinue }
        if ($tkM) { Import-Module $tkM.Name -Force -ErrorAction SilentlyContinue; if (Get-Command 'Connect-NSGroup' -ErrorAction SilentlyContinue) { $tkAvail=$true } }
        if ($tkAvail) { $tkR = _Collect_Toolkit }
        else { Write-Host "`n=== TOOLKIT ===" -ForegroundColor Magenta; Write-Host "  [SKIP] Not available (PS $($PSVersionTable.PSVersion))" -ForegroundColor Yellow }
    }

    # REST
    if ($CollectionMode -in @('Both','REST')) { $reR = _Collect_REST }

    # Build + Export
    if ($tkR -and $tkR.Success) {
        $tkRpt = _BuildReport -Raw $tkR -Src 'Toolkit'
        if (-not $ArrayName) { $ArrayName = $script:_detName }; if (-not $ArrayName) { $ArrayName = 'NimbleArray' }
        _Export -Rpt $tkRpt -Src 'Toolkit' -Dir $OutputPath -Arr $ArrayName -FTS $fileTS
    }
    if ($reR -and $reR.Success) {
        $reRpt = _BuildReport -Raw $reR -Src 'REST'
        if (-not $ArrayName) { $ArrayName = $script:_detName }; if (-not $ArrayName) { $ArrayName = 'NimbleArray' }
        _Export -Rpt $reRpt -Src 'REST' -Dir $OutputPath -Arr $ArrayName -FTS $fileTS
    }

    # Comparison
    if ($CollectionMode -eq 'Both') {
        Write-Host "`n================================================================" -ForegroundColor Cyan
        Write-Host "  METHOD COMPARISON" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan
        $tkOK = if ($tkR -and $tkR.Success) { 'PASS' } else { 'FAIL' }
        $reOK = if ($reR -and $reR.Success) { 'PASS' } else { 'FAIL' }
        Write-Host "`n  Method           Status Duration  Arrays Vols  Disks FC-Sess LUNs  Snaps Alarms" -ForegroundColor White
        Write-Host "  ---------------- ------ --------- ------ ----- ----- ------- ----- ----- ------" -ForegroundColor DarkGray
        foreach ($m in @(@{N='Toolkit (NS)  ';R=$tkR;S=$tkOK},@{N='REST API       ';R=$reR;S=$reOK})) {
            if ($m.R) {
                $dur = if($m.R.Duration){$m.R.Duration.TotalSeconds.ToString('F1')+'s'}else{'N/A'}
                $line = "  {0} {1,-6} {2,-9} {3,-6} {4,-5} {5,-5} {6,-7} {7,-5} {8,-5} {9}" -f $m.N, $m.S, $dur,
                    $(if($m.R.Arrays){$m.R.Arrays.Count}else{0}), $(if($m.R.Volumes){$m.R.Volumes.Count}else{0}),
                    $(if($m.R.Disks){$m.R.Disks.Count}else{0}), $(if($m.R.FCSessions){$m.R.FCSessions.Count}else{0}),
                    $(if($m.R.ACRecords){$m.R.ACRecords.Count}else{0}), $(if($m.R.Snapshots){$m.R.Snapshots.Count}else{0}),
                    $(if($m.R.Alarms){$m.R.Alarms.Count}else{0})
                $c = if($m.S -eq 'PASS'){'Green'}else{'Red'}; Write-Host $line -ForegroundColor $c
                if ($m.S -eq 'FAIL' -and $m.R.Error) { Write-Host "                   Error: $($m.R.Error)" -ForegroundColor Red }
            } else { Write-Host "  $($m.N) SKIP   N/A       (not available)" -ForegroundColor Yellow }
        }
        Write-Host ""
        if ($tkOK -eq 'PASS' -and $reOK -eq 'PASS') { Write-Host "  BOTH methods work. REST API confirmed as PS 5.1 fallback." -ForegroundColor Green }
        elseif ($reOK -eq 'PASS') { Write-Host "  REST works. Toolkit unavailable (expected in PS 5.1)." -ForegroundColor Yellow }
        elseif ($tkOK -eq 'PASS') { Write-Host "  Toolkit works. REST failed -- check port 5392." -ForegroundColor Yellow }
        else { Write-Host "  BOTH FAILED. Check credentials and network to $ArrayIP." -ForegroundColor Red }
    }

    Write-Host "`n================================================================" -ForegroundColor Cyan
    Write-Host "  Collection complete." -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
}
