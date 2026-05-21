<#
.SYNOPSIS
    Test-IsilonConnectivity.ps1 v2
    Auto-discovers correct API versions for OneFS 9.x endpoints.

.DESCRIPTION
    Dot-source then call. Tests session auth + discovers working API version
    for each endpoint category (nodes, stats, events, storage pools, snapshots).

.NOTES
    Author: Michael George | Version: 2.0.0 | Date: 2026-03-22
#>

function Test-IsilonConnectivity {
    [CmdletBinding()]
    param(
        [string]$ClusterIP = '10.91.25.21',
        [System.Management.Automation.PSCredential]$Credential,
        [int]$Port = 8080
    )

    $isPS7 = ($PSVersionTable.PSVersion.Major -ge 7)
    if (-not $isPS7) {
        if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
            Add-Type 'using System.Net; using System.Security.Cryptography.X509Certificates; public class TrustAllCertsPolicy : ICertificatePolicy { public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; } }'
        }
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    }

    if (-not $Credential) { $Credential = Get-Credential -Message "Isilon ($ClusterIP)" }
    if (-not $Credential) { Write-Error "No credential."; return }

    $baseUrl = "https://${ClusterIP}:${Port}"

    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  Isilon / PowerScale Connectivity & API Discovery" -ForegroundColor Cyan
    Write-Host "  Target: $baseUrl | User: $($Credential.UserName)" -ForegroundColor Cyan
    Write-Host "  PS: $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)" -ForegroundColor Cyan
    Write-Host "================================================================`n" -ForegroundColor Cyan

    # --- Session auth ---
    Write-Host "[Auth] Establishing session..." -NoNewline
    $session = $null; $csrfToken = $null

    try {
        $authBody = @{ username = $Credential.UserName; password = $Credential.GetNetworkCredential().Password; services = @('platform') } | ConvertTo-Json
        $authParams = @{ Uri = "$baseUrl/session/1/session"; Method = 'Post'; Body = $authBody; ContentType = 'application/json'; SessionVariable = 'isilonSession'; ErrorAction = 'Stop' }
        if ($isPS7) { $authParams['SkipCertificateCheck'] = $true }
        $null = Invoke-WebRequest @authParams
        $session = $isilonSession
        $csrfCookie = $session.Cookies.GetCookies($baseUrl) | Where-Object { $_.Name -eq 'isicsrf' }
        if ($csrfCookie) { $csrfToken = $csrfCookie.Value }
        Write-Host " OK (session + CSRF)" -ForegroundColor Green
    }
    catch {
        Write-Host " FAIL: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Cannot proceed without session auth." -ForegroundColor Red
        return
    }

    # --- Helper: make authenticated GET ---
    function _Get {
        param([string]$Path)
        $p = @{ Uri = "$baseUrl$Path"; Method = 'Get'; WebSession = $session; ContentType = 'application/json'; ErrorAction = 'Stop' }
        if ($csrfToken) { $p['Headers'] = @{ 'Referer' = $baseUrl; 'X-CSRF-Token' = $csrfToken } }
        if ($isPS7) { $p['SkipCertificateCheck'] = $true }
        return Invoke-RestMethod @p
    }

    # --- Discover working API version for each endpoint ---
    # OneFS PAPI versions: 1-17+ (OneFS 9.2 typically uses versions 1-12)
    # Try multiple versions to find the right one

    $results = @()
    $discoveredVersions = @{}

    # Endpoints to test with version discovery
    $endpointTests = @(
        @{ Name = 'Cluster Identity';   Versions = @(1);         Path = 'cluster/identity' }
        @{ Name = 'Cluster Config';     Versions = @(3,5,1,7);   Path = 'cluster/config' }
        @{ Name = 'Cluster Nodes';      Versions = @(3,5,7,9,1); Path = 'cluster/nodes' }
        @{ Name = 'Storage Pools';      Versions = @(9,7,5,3,1); Path = 'storagepool/storagepools' }
        @{ Name = 'SMB Shares';         Versions = @(1,3,5,7);   Path = 'protocols/smb/shares' }
        @{ Name = 'NFS Exports';        Versions = @(1,3,5,7);   Path = 'protocols/nfs/exports' }
        @{ Name = 'Quotas';             Versions = @(1,3,5,7);   Path = 'quota/quotas' }
        @{ Name = 'Snapshots';          Versions = @(1,3,5,7);   Path = 'snapshot/snapshots' }
        @{ Name = 'Snap Schedules';     Versions = @(1,3,5,7);   Path = 'snapshot/schedules' }
        @{ Name = 'Sync Policies';      Versions = @(1,3,5,7);   Path = 'sync/policies' }
        @{ Name = 'Events';             Versions = @(7,5,3,1);   Path = 'event/eventlists' }
        @{ Name = 'Alarms';             Versions = @(12,9,7,5);  Path = 'event/alert-conditions' }
        @{ Name = 'Statistics Keys';    Versions = @(3,1,5,7);   Path = 'statistics/keys' }
        @{ Name = 'HW Status';         Versions = @(5,3,1,7);   Path = 'cluster/statfs' }
        @{ Name = 'Network Interfaces'; Versions = @(7,5,3,1);   Path = 'network/interfaces' }
        @{ Name = 'Zones';             Versions = @(1,3);        Path = 'zones' }
    )

    foreach ($ep in $endpointTests) {
        Write-Host "  $($ep.Name)..." -NoNewline
        $found = $false

        foreach ($ver in $ep.Versions) {
            $testPath = "/platform/$ver/$($ep.Path)"
            try {
                $response = _Get -Path $testPath
                # Summarize response
                $detail = "v$ver"
                $propNames = @($response.PSObject.Properties.Name)
                if ($propNames.Count -gt 0) {
                    $firstProp = $propNames[0]
                    $firstVal = $response.$firstProp
                    if ($firstVal -is [array]) {
                        $detail += " -- $($firstVal.Count) item(s)"
                    }
                    elseif ($firstVal -is [string]) {
                        $short = $firstVal.Substring(0, [Math]::Min(50, $firstVal.Length))
                        $detail += " -- ${firstProp}: $short"
                    }
                    $detail += " [props: $($propNames -join ', ')]"
                }

                Write-Host " OK ($detail)" -ForegroundColor Green
                $results += [PSCustomObject]@{ Endpoint = $ep.Name; Status = 'PASS'; APIVersion = $ver; Path = $testPath; Detail = $detail }
                $discoveredVersions[$ep.Name] = $ver
                $found = $true
                break
            }
            catch {
                # Try next version
            }
        }

        if (-not $found) {
            Write-Host " FAIL (tried versions: $($ep.Versions -join ', '))" -ForegroundColor Red
            $results += [PSCustomObject]@{ Endpoint = $ep.Name; Status = 'FAIL'; APIVersion = 'N/A'; Path = ''; Detail = "None of versions $($ep.Versions -join ',') worked" }
        }
    }

    # --- Also test raw statistics with a known key ---
    Write-Host "  Statistics (ifs.bytes)..." -NoNewline
    $statsFound = $false
    foreach ($ver in @(3,1,5,7)) {
        foreach ($keyFormat in @(
            "statistics/current?key=ifs.bytes.avail",
            "statistics/current?keys=ifs.bytes.avail",
            "statistics/summary?key=ifs.bytes.avail",
            "statistics/current?key=ifs.bytes.total"
        )) {
            try {
                $sr = _Get -Path "/platform/$ver/$keyFormat"
                if ($sr) {
                    $detail = "v$ver -- $keyFormat"
                    if ($sr.stats) { $detail += " ($($sr.stats.Count) stat(s))" }
                    Write-Host " OK ($detail)" -ForegroundColor Green
                    $results += [PSCustomObject]@{ Endpoint = 'Statistics'; Status = 'PASS'; APIVersion = $ver; Path = "/platform/$ver/$keyFormat"; Detail = $detail }
                    $discoveredVersions['Statistics'] = $ver
                    $statsFound = $true
                    break
                }
            } catch {}
        }
        if ($statsFound) { break }
    }
    if (-not $statsFound) {
        Write-Host " FAIL" -ForegroundColor Red
        $results += [PSCustomObject]@{ Endpoint = 'Statistics'; Status = 'FAIL'; APIVersion = 'N/A'; Path = ''; Detail = 'No stats endpoint found' }
    }

    # --- Also try storagepool nodepool for disk/capacity info ---
    Write-Host "  Node Pools..." -NoNewline
    $npFound = $false
    foreach ($ver in @(9,7,5,3,1)) {
        try {
            $np = _Get -Path "/platform/$ver/storagepool/nodepools"
            if ($np) {
                $count = if ($np.nodepools) { $np.nodepools.Count } else { 0 }
                Write-Host " OK (v$ver -- $count pool(s))" -ForegroundColor Green
                $results += [PSCustomObject]@{ Endpoint = 'Node Pools'; Status = 'PASS'; APIVersion = $ver; Path = "/platform/$ver/storagepool/nodepools"; Detail = "v$ver -- $count pool(s)" }
                $discoveredVersions['Node Pools'] = $ver
                $npFound = $true
                break
            }
        } catch {}
    }
    if (-not $npFound) {
        Write-Host " FAIL" -ForegroundColor Red
        $results += [PSCustomObject]@{ Endpoint = 'Node Pools'; Status = 'FAIL'; APIVersion = 'N/A'; Path = ''; Detail = 'Not found' }
    }

    # --- Summary ---
    Write-Host "`n================================================================" -ForegroundColor Cyan
    Write-Host "  API DISCOVERY RESULTS -- $ClusterIP" -ForegroundColor Cyan
    Write-Host "================================================================`n" -ForegroundColor Cyan

    $results | Format-Table Endpoint, Status, APIVersion, Path, Detail -AutoSize

    $passCount = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
    $failCount = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count

    Write-Host "  $passCount PASS, $failCount FAIL out of $($results.Count) endpoints" -ForegroundColor $(if ($failCount -eq 0) { 'Green' } elseif ($failCount -lt 5) { 'Yellow' } else { 'Red' })

    if ($discoveredVersions.Count -gt 0) {
        Write-Host "`n  Discovered API versions for full inventory script:" -ForegroundColor Cyan
        foreach ($k in $discoveredVersions.Keys | Sort-Object) {
            Write-Host "    $k = v$($discoveredVersions[$k])" -ForegroundColor White
        }
    }

    Write-Host "`n================================================================" -ForegroundColor Cyan
    return $results
}
