<#
.SYNOPSIS
    Test-NetAppConnectivity.ps1
    Quick connectivity and API validation for NetApp ONTAP clusters.

.DESCRIPTION
    Dot-source then call:
      . .\Test-NetAppConnectivity.ps1
      Test-NetAppConnectivity -ClusterIP '10.91.1.43' -Credential (Get-Credential)

    Tests ONTAP REST API endpoints at https://<ip>/api/*
    ONTAP 9.6+ uses Basic auth on every request (no session/CSRF needed).

.NOTES
    Author: Michael George | Version: 1.0.0 | Date: 2026-03-22 | PS: 5.1+
#>

function Test-NetAppConnectivity {
    [CmdletBinding()]
    param(
        [string]$ClusterIP = '10.91.1.43',
        [System.Management.Automation.PSCredential]$Credential,
        [int]$Port = 443
    )

    $isPS7 = ($PSVersionTable.PSVersion.Major -ge 7)
    if (-not $isPS7) {
        if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
            Add-Type 'using System.Net; using System.Security.Cryptography.X509Certificates; public class TrustAllCertsPolicy : ICertificatePolicy { public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; } }'
        }
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    }

    if (-not $Credential) { $Credential = Get-Credential -Message "NetApp ONTAP ($ClusterIP) -- root or admin" }
    if (-not $Credential) { Write-Error "No credential."; return }

    $baseUrl = "https://${ClusterIP}"

    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  NetApp ONTAP REST API Connectivity Test" -ForegroundColor Cyan
    Write-Host "  Target: $baseUrl | User: $($Credential.UserName)" -ForegroundColor Cyan
    Write-Host "  PS: $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)" -ForegroundColor Cyan
    Write-Host "================================================================`n" -ForegroundColor Cyan

    # ONTAP REST API uses Basic auth on every request
    $encoded = [System.Convert]::ToBase64String(
        [System.Text.Encoding]::UTF8.GetBytes("$($Credential.UserName):$($Credential.GetNetworkCredential().Password)")
    )
    $headers = @{ Authorization = "Basic $encoded"; Accept = 'application/json' }

    function _Get {
        param([string]$Path)
        $p = @{ Uri = "${baseUrl}${Path}"; Method = 'Get'; Headers = $headers; ContentType = 'application/json'; ErrorAction = 'Stop' }
        if ($isPS7) { $p['SkipCertificateCheck'] = $true }
        else { $p['UseBasicParsing'] = $true }
        return Invoke-RestMethod @p
    }

    $results = @()

    # TCP test
    Write-Host "[1] TCP connectivity to ${ClusterIP}:${Port}..." -NoNewline
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($ClusterIP, $Port)
        $tcp.Close()
        Write-Host " OK" -ForegroundColor Green
        $results += [PSCustomObject]@{ Endpoint='TCP Connect'; Status='PASS'; Detail="Port $Port open" }
    }
    catch {
        Write-Host " FAIL" -ForegroundColor Red
        $results += [PSCustomObject]@{ Endpoint='TCP Connect'; Status='FAIL'; Detail=$_.Exception.Message }
        $results | Format-Table -AutoSize; return $results
    }

    # API endpoints to test
    $endpoints = @(
        @{ Name='Cluster Info';        Path='/api/cluster';                     Key='name' }
        @{ Name='Cluster Nodes';       Path='/api/cluster/nodes';               Key='records' }
        @{ Name='Cluster Version';     Path='/api/cluster?fields=version';      Key='version' }
        @{ Name='Aggregates';          Path='/api/storage/aggregates';          Key='records' }
        @{ Name='Volumes';             Path='/api/storage/volumes';             Key='records' }
        @{ Name='Volume Detail';       Path='/api/storage/volumes?fields=name,size,state,type,style,svm,aggregates,space,nas'; Key='records' }
        @{ Name='Disks';               Path='/api/storage/disks';              Key='records' }
        @{ Name='Shelves';             Path='/api/storage/shelves';            Key='records' }
        @{ Name='SVMs';                Path='/api/svm/svms';                   Key='records' }
        @{ Name='Network Interfaces';  Path='/api/network/ip/interfaces';      Key='records' }
        @{ Name='Network Ports';       Path='/api/network/ethernet/ports';     Key='records' }
        @{ Name='FC Interfaces';       Path='/api/network/fc/interfaces';      Key='records' }
        @{ Name='FC Ports';            Path='/api/network/fc/ports';           Key='records' }
        @{ Name='SMB Shares';          Path='/api/protocols/cifs/shares';      Key='records' }
        @{ Name='NFS Exports';         Path='/api/protocols/nfs/export-policies'; Key='records' }
        @{ Name='iSCSI LIFs';          Path='/api/protocols/san/iscsi/services'; Key='records' }
        @{ Name='LUNs';                Path='/api/storage/luns';               Key='records' }
        @{ Name='Snapshots (vol1)';    Path='/api/storage/volumes?fields=snapshot_count'; Key='records' }
        @{ Name='SnapMirror';          Path='/api/snapmirror/relationships';   Key='records' }
        @{ Name='Events';              Path='/api/support/ems/events?max_records=5'; Key='records' }
        @{ Name='Alerts';              Path='/api/private/support/alerts';     Key='records' }
        @{ Name='Cluster Health';      Path='/api/private/cli/system/health/status/show'; Key='' }
    )

    $i = 2
    foreach ($ep in $endpoints) {
        Write-Host "[$i] $($ep.Name)..." -NoNewline
        try {
            $response = _Get -Path $ep.Path
            $detail = ''
            if ($ep.Key -eq 'records' -and $response.records) {
                $count = $response.num_records
                if (-not $count) { $count = $response.records.Count }
                $detail = "$count item(s)"
                if ($count -gt 0 -and $response.records[0].name) {
                    $first3 = ($response.records | Select-Object -First 3 | ForEach-Object { $_.name }) -join ', '
                    $detail += " -- $first3"
                }
            }
            elseif ($ep.Key -eq 'name' -and $response.name) {
                $detail = "Name: $($response.name)"
                if ($response.uuid) { $detail += ", UUID: $($response.uuid.Substring(0,8))..." }
            }
            elseif ($ep.Key -eq 'version' -and $response.version) {
                $v = $response.version
                $detail = "ONTAP $($v.full)"
                if (-not $v.full -and $v.generation) { $detail = "ONTAP $($v.generation).$($v.major).$($v.minor)" }
            }
            else {
                $propNames = @($response.PSObject.Properties.Name)
                $detail = "OK [props: $($propNames -join ', ')]"
            }

            Write-Host " OK -- $detail" -ForegroundColor Green
            $results += [PSCustomObject]@{ Endpoint=$ep.Name; Status='PASS'; Detail=$detail }
        }
        catch {
            $errMsg = $_.Exception.Message
            # Check for 404 vs 401 vs other
            if ($errMsg -match '404') { $errMsg = 'Not Found (endpoint may not exist on this ONTAP version)' }
            elseif ($errMsg -match '401') { $errMsg = 'Unauthorized (check credentials)' }
            Write-Host " FAIL -- $errMsg" -ForegroundColor Red
            $results += [PSCustomObject]@{ Endpoint=$ep.Name; Status='FAIL'; Detail=$errMsg }
        }
        $i++
    }

    # Summary
    Write-Host "`n================================================================" -ForegroundColor Cyan
    Write-Host "  RESULTS SUMMARY -- $ClusterIP" -ForegroundColor Cyan
    Write-Host "================================================================`n" -ForegroundColor Cyan

    $results | Format-Table Endpoint, Status, Detail -AutoSize

    $passCount = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
    $failCount = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count

    $c = if ($failCount -eq 0) { 'Green' } elseif ($failCount -lt 5) { 'Yellow' } else { 'Red' }
    Write-Host "  $passCount PASS, $failCount FAIL out of $($results.Count) endpoints" -ForegroundColor $c

    if ($failCount -eq 0) { Write-Host "  All endpoints accessible. Ready to build full inventory script." -ForegroundColor Green }
    elseif ($passCount -gt 5) { Write-Host "  Partial access. Some endpoints may require different permissions or ONTAP version." -ForegroundColor Yellow }
    else { Write-Host "  Most endpoints failed. Check credentials and ONTAP version." -ForegroundColor Red }

    Write-Host "================================================================`n" -ForegroundColor Cyan
    return $results
}
