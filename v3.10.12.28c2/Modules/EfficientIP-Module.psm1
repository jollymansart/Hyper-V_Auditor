<#
.SYNOPSIS
    Advanced EfficientIP SOLIDserver API PowerShell Module

.DESCRIPTION
    Comprehensive module for interacting with EfficientIP SOLIDserver REST API
    Provides functions for subnet discovery, device enumeration, and VLAN filtering

.NOTES
    Author: Michael David George
    Date: 2025-01-21
    Version: 3.10.12
    
    API Documentation Reference:
    - REST Format: https://<server>/rest/<service>?param=value
    - Services: *_list, *_info, *_count, *_add, *_delete
    - WHERE clause support for filtering
    - ORDERBY clause support for sorting

    import-module \\rictx-script-p2\Script_Dev\Powershell\Modules\EfficentIP\v1.1.5\EfficientIP-Module.psm1

        # Import the module
Import-Module \\rictx-script-p2\Script_Dev\Powershell\Modules\EfficentIP\v1.1.5\EfficientIP-Module.psm1

# Connect to EfficientIP
$credential = Get-Credential  # Use your EfficientIP credentials
$config = Connect-EfficientIP -Server "RICTX-IPAM-P01.ohdc.com" -Credential $credential -IgnoreSSL
# Exact hostname match
Get-EfficientIPByHostname -Config $config -Hostname "PENFL2P16.ohdc.com"

# Partial hostname search
Get-EfficientIPByHostname -Config $config -Hostname "PENFL2P16"

# Select specific fields
Get-EfficientIPByHostname -Config $config -Hostname "PENFL2P16.ohdc.com" |
    Select-Object IPAddress, IPAddressHex, name, mac_addr, subnet_name


    # Examples
Convert-HexToIP -HexAddress "0ad7bb74"
# Returns: 10.215.187.116

"c0a80101" | Convert-HexToIP
# Returns: 192.168.1.1

# Examples
Convert-IPToHex -IPAddress "10.215.187.116"
# Returns: 0ad7bb74

"192.168.1.1" | Convert-IPToHex
# Returns: c0a80101



# Using decimal format
Get-EfficientIPByIP -Config $config -IPAddress "10.215.187.116"

# Using hex format
Get-EfficientIPByIP -Config $config -IPAddress "0ad7bb74"

# Pipeline support
"10.215.187.116" | Get-EfficientIPByIP -Config $config |
    Format-Table IPAddress, IPAddressHex, name, mac_addr, subnet_name








    # Example: Combine EfficientIP data with Forescout printer inventory
$printers = Import-Csv "C:\Reports\Forescout_Printers.csv"

$enrichedData = foreach ($printer in $printers) {
    $ipamData = Get-EfficientIPByIP -Config $config -IPAddress $printer.IPAddress -ErrorAction SilentlyContinue
    
    [PSCustomObject]@{
        PrinterName = $printer.Name
        IPAddress = $printer.IPAddress
        IPAddressHex = if ($ipamData) { $ipamData.IPAddressHex } else { "Not in IPAM" }
        MACAddress = $printer.MACAddress
        IPAM_MAC = if ($ipamData) { $ipamData.mac_addr } else { "Not in IPAM" }
        Subnet = if ($ipamData) { $ipamData.subnet_name } else { "Unknown" }
        Site = if ($ipamData) { $ipamData.site_name } else { "Unknown" }
        DNSName = if ($ipamData) { $ipamData.name } else { "Not Registered" }
        LastSeen = $printer.LastSeen
    }
}

$enrichedData | Export-Csv "C:\Reports\Printers_Enriched.csv" -NoTypeInformation



#>

#region Initialization

# Load System.Web assembly for URL encoding (if available)
# If not available, we'll use a custom function
$script:UseSystemWeb = $false
try {
    Add-Type -AssemblyName System.Web -ErrorAction Stop
    $script:UseSystemWeb = $true
}
catch {
    # System.Web not available, will use custom encoding
    $script:UseSystemWeb = $false
}

# Custom URL encoding function (fallback)
function ConvertTo-UrlEncoded {
    param([string]$Value)
    
    if ([string]::IsNullOrEmpty($Value)) {
        return ""
    }
    
    # Simple URL encoding for common characters
    $Value = $Value.Replace('%', '%25')
    $Value = $Value.Replace(' ', '%20')
    $Value = $Value.Replace('!', '%21')
    $Value = $Value.Replace('"', '%22')
    $Value = $Value.Replace('#', '%23')
    $Value = $Value.Replace('$', '%24')
    $Value = $Value.Replace('&', '%26')
    $Value = $Value.Replace("'", '%27')
    $Value = $Value.Replace('(', '%28')
    $Value = $Value.Replace(')', '%29')
    $Value = $Value.Replace('*', '%2A')
    $Value = $Value.Replace('+', '%2B')
    $Value = $Value.Replace(',', '%2C')
    $Value = $Value.Replace('/', '%2F')
    $Value = $Value.Replace(':', '%3A')
    $Value = $Value.Replace(';', '%3B')
    $Value = $Value.Replace('=', '%3D')
    $Value = $Value.Replace('?', '%3F')
    $Value = $Value.Replace('@', '%40')
    $Value = $Value.Replace('[', '%5B')
    $Value = $Value.Replace(']', '%5D')
    
    return $Value
}

# Wrapper function for URL encoding
function Get-UrlEncoded {
    param([string]$Value)
    
    if ($script:UseSystemWeb) {
        return [System.Web.HttpUtility]::UrlEncode($Value)
    }
    else {
        return ConvertTo-UrlEncoded -Value $Value
    }
}

#endregion

#region Hex Conversion

function Convert-IPToHex {
    <#
    .SYNOPSIS
        Converts an IP address to EfficientIP's hexadecimal format.
    
    .DESCRIPTION
        Converts a standard dotted-decimal IP address (e.g., 10.215.187.116) 
        to EfficientIP's 8-character hexadecimal format (e.g., 0ad7bb74).
    
    .PARAMETER IPAddress
        The IP address in dotted-decimal format (e.g., 192.168.1.100)
    
    .EXAMPLE
        Convert-IPToHex -IPAddress "10.215.187.116"
        Returns: 0ad7bb74
    
    .EXAMPLE
        "192.168.1.1" | Convert-IPToHex
        Returns: c0a80101
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidatePattern('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')]
        [string]$IPAddress
    )
    
    process {
        try {
            $octets = $IPAddress.Split('.')
            
            # Validate each octet is 0-255
            foreach ($octet in $octets) {
                $value = [int]$octet
                if ($value -lt 0 -or $value -gt 255) {
                    throw "Invalid IP address: Octet value $value is out of range (0-255)"
                }
            }
            
            # Convert each octet to 2-character hex and join
            $hexParts = @()
            foreach ($octet in $octets) {
                $hexParts += ([int]$octet).ToString('x2')
            }
            
            return ($hexParts -join '')
        }
        catch {
            Write-Error "Failed to convert IP address '$IPAddress' to hex: $_"
            throw
        }
    }
}

function Convert-HexToIP {
    <#
    .SYNOPSIS
        Converts EfficientIP's hexadecimal format to a standard IP address.
    
    .DESCRIPTION
        Converts an 8-character hexadecimal IP address (e.g., 0ad7bb74) 
        to standard dotted-decimal format (e.g., 10.215.187.116).
    
    .PARAMETER HexAddress
        The hexadecimal IP address (8 characters, e.g., 0ad7bb74)
    
    .EXAMPLE
        Convert-HexToIP -HexAddress "0ad7bb74"
        Returns: 10.215.187.116
    
    .EXAMPLE
        "c0a80101" | Convert-HexToIP
        Returns: 192.168.1.1
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidatePattern('^[0-9a-fA-F]{8}$')]
        [string]$HexAddress
    )
    
    process {
        try {
            # Convert to lowercase for consistency
            $hex = $HexAddress.ToLower()
            
            # Extract each octet (2 hex chars = 1 byte)
            if ($hex -match '^([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$') {
                $octet1 = [convert]::ToInt32($matches[1], 16)
                $octet2 = [convert]::ToInt32($matches[2], 16)
                $octet3 = [convert]::ToInt32($matches[3], 16)
                $octet4 = [convert]::ToInt32($matches[4], 16)
                
                return "$octet1.$octet2.$octet3.$octet4"
            }
            else {
                throw "Invalid hexadecimal format. Expected 8 characters (e.g., 0ad7bb74)"
            }
        }
        catch {
            Write-Error "Failed to convert hex address '$HexAddress' to IP: $_"
            throw
        }
    }
}

#endregion

#region Configuration


#==============================================================================
# HELPER FUNCTION - Usage Guide
#==============================================================================

function Show-ConnectEfficientIPHelp {
    Write-Host ""
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host "  Connect-EfficientIP Usage Guide" -ForegroundColor Cyan
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "BASIC USAGE:" -ForegroundColor Yellow
    Write-Host "  `$credential = Get-Credential" -ForegroundColor White
    Write-Host "  `$ipamConfig = Connect-EfficientIP -Server 'RICTX-IPAM-P01.ohdc.com' -Credential `$credential -IgnoreSSL" -ForegroundColor White
    Write-Host ""
    
    Write-Host "WITH EXPORT-PRINTERINVENTORY:" -ForegroundColor Yellow
    Write-Host "  `$credential = Get-Credential" -ForegroundColor White
    Write-Host "  `$ipamConfig = Connect-EfficientIP -Server 'RICTX-IPAM-P01.ohdc.com' -Credential `$credential -IgnoreSSL" -ForegroundColor White
    Write-Host "  Export-PrinterInventory -EnableIPAM -IPAMConfig `$ipamConfig -Verbose" -ForegroundColor White
    Write-Host ""
    
    Write-Host "LOOKUP IP ADDRESS:" -ForegroundColor Yellow
    Write-Host "  `$result = Get-EfficientIPAddress -IPAMConfig `$ipamConfig -IPAddress '10.0.0.100'" -ForegroundColor White
    Write-Host ""
    
    Write-Host "MORE HELP: Get-Help Connect-EfficientIP -Full" -ForegroundColor Yellow
    Write-Host ""
}

#Export-ModuleMember -Function 'Show-ConnectEfficientIPHelp'


function New-EfficientIPConfig {
    param(
        [string]$Server,
        [PSCredential]$Credential,
        [bool]$IgnoreSSL
    )
    
    $config = [PSCustomObject]@{
        Server = $Server
        Credential = $Credential
        IgnoreSSL = $IgnoreSSL
        Headers = $null
        BaseUrl = "https://$Server/rest"
    }
    
    # Initialize headers
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(
        ("{0}:{1}" -f $Credential.UserName, $Credential.GetNetworkCredential().Password)
    ))
    
    $config.Headers = @{
        'Authorization' = "Basic $base64AuthInfo"
        'Accept' = 'application/json'
        'Content-Type' = 'application/json'
    }
    
    # Configure SSL
    if ($IgnoreSSL) {
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            # PowerShell 5.1 SSL bypass
            if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
                $certPolicy = @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
                Add-Type -TypeDefinition $certPolicy
            }
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
        }
    }
    
    return $config
}

#endregion

#region Core API Functions

function Connect-EfficientIP {
    <#
    .SYNOPSIS
        Establish connection to EfficientIP SOLIDserver
    
    .EXAMPLE
        $config = Connect-EfficientIP -Server "RICTX-IPAM-P01.ohdc.com" -Credential $cred
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Server,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        
        [switch]$IgnoreSSL
    )
    
    $config = New-EfficientIPConfig -Server $Server -Credential $Credential -IgnoreSSL $IgnoreSSL.IsPresent
    
    # Test connection
    try {
        # Use ip_block_subnet_list instead of ip_subnet_list
        # This is the correct service name from the API documentation
        $testUrl = "$($config.BaseUrl)/ip_block_subnet_list"
        $testParams = @{ LIMIT = "1" }
        
        $paramString = ($testParams.GetEnumerator() | ForEach-Object {
            "$($_.Key)=$(Get-UrlEncoded -Value $_.Value)"
        }) -join '&'
        
        $fullUrl = "$testUrl`?$paramString"
        
        Write-Verbose "Test URL: $fullUrl"
        Write-Verbose "Headers: $($config.Headers.Keys -join ', ')"
        
        $splat = @{
            Uri = $fullUrl
            Method = 'Get'
            Headers = $config.Headers
            ErrorAction = 'Stop'
            UseBasicParsing = $true
        }
        
        # Add SkipCertificateCheck only for PowerShell 7+
        if ($PSVersionTable.PSVersion.Major -ge 6 -and $config.IgnoreSSL) {
            $splat['SkipCertificateCheck'] = $true
        }
        
        Write-Verbose "Attempting connection..."
        $test = Invoke-RestMethod @splat
        Write-Host "[OK] Successfully connected to EfficientIP SOLIDserver: $Server" -ForegroundColor Green
        return $config
    }
    catch {
        Write-Error "Failed to connect to EfficientIP: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $responseBody = $reader.ReadToEnd()
                Write-Verbose "Response body: $responseBody"
            }
            catch {
                Write-Verbose "Could not read response body"
            }
        }
        Write-Verbose "Full URL attempted: $fullUrl"
        throw
    }
}

function Invoke-EfficientIPAPI {
    <#
    .SYNOPSIS
        Execute EfficientIP REST API call
    
    .EXAMPLE
        $result = Invoke-EfficientIPAPI -Config $config -Service "ip_subnet_list"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,
        
        [Parameter(Mandatory=$true)]
        [string]$Service,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$Parameters = @{},
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Get', 'Post', 'Put', 'Delete')]
        [string]$Method = 'Get'
    )
    
    # Build URL
    $url = "$($Config.BaseUrl)/$Service"
    
    # Add parameters
    if ($Parameters.Count -gt 0) {
        $paramString = ($Parameters.GetEnumerator() | ForEach-Object {
            "$($_.Key)=$(Get-UrlEncoded -Value $_.Value)"
        }) -join '&'
        $url = "$url`?$paramString"
    }
    
    Write-Verbose "API Call: $Method $url"
    
    $splat = @{
        Uri = $url
        Method = $Method
        Headers = $Config.Headers
        ErrorAction = 'Stop'
        UseBasicParsing = $true
    }
    
    # Add SkipCertificateCheck only for PowerShell 7+
    if ($PSVersionTable.PSVersion.Major -ge 6 -and $Config.IgnoreSSL) {
        $splat['SkipCertificateCheck'] = $true
    }
    
    try {
        # PowerShell 5.1 and 7+ compatible
        $response = Invoke-RestMethod @splat
        return $response
    }
    catch {
        Write-Error "API call failed: $($_.Exception.Message)"
        if ($_.ErrorDetails.Message) {
            Write-Error "Details: $($_.ErrorDetails.Message)"
        }
        throw
    }
}

#endregion

#region Subnet Functions

function Get-EfficientIPSubnet {
    <#
    .SYNOPSIS
        Retrieve subnets from EfficientIP
    
    .EXAMPLE
        Get-EfficientIPSubnet -Config $config
        Get-EfficientIPSubnet -Config $config -Filter "subnet_name like '%VLAN40%'"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,
        
        [Parameter(Mandatory=$false)]
        [string]$Filter,
        
        [Parameter(Mandatory=$false)]
        [int]$Limit,
        
        [Parameter(Mandatory=$false)]
        [string]$OrderBy
    )
    
    $params = @{}
    
    if ($Filter) {
        $params['WHERE'] = $Filter
    }
    
    if ($Limit) {
        $params['LIMIT'] = $Limit.ToString()
    }
    
    if ($OrderBy) {
        $params['ORDERBY'] = $OrderBy
    }
    
    try {
        $result = Invoke-EfficientIPAPI -Config $Config -Service "ip_block_subnet_list" -Parameters $params
        
        # Process and return results
        if ($result) {
            return $result
        }
        else {
            return @()
        }
    }
    catch {
        Write-Error "Failed to retrieve subnets: $($_.Exception.Message)"
        throw
    }
}

function Get-EfficientIPSubnetInfo {
    <#
    .SYNOPSIS
        Get detailed information about a specific subnet
    
    .EXAMPLE
        Get-EfficientIPSubnetInfo -Config $config -SubnetId 12345
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,
        
        [Parameter(Mandatory=$true)]
        [string]$SubnetId
    )
    
    $params = @{
        'subnet_id' = $SubnetId
    }
    
    try {
        $result = Invoke-EfficientIPAPI -Config $Config -Service "ip_subnet_info" -Parameters $params
        return $result
    }
    catch {
        Write-Error "Failed to retrieve subnet info: $($_.Exception.Message)"
        throw
    }
}

#endregion

#region IP Address Functions

function Get-EfficientIPAddress {
    <#
    .SYNOPSIS
        Retrieve IP addresses from EfficientIP
    
    .EXAMPLE
        Get-EfficientIPAddress -Config $config -SubnetId 12345
        Get-EfficientIPAddress -Config $config -Filter "ip_name like '%server%'"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,
        
        [Parameter(Mandatory=$false)]
        [string]$SubnetId,
        
        [Parameter(Mandatory=$false)]
        [string]$Filter,
        
        [Parameter(Mandatory=$false)]
        [int]$Limit
    )
    
    $params = @{}
    
    # Build WHERE clause
    $whereClauses = @()
    
    if ($SubnetId) {
        $whereClauses += "subnet_id='$SubnetId'"
    }
    
    if ($Filter) {
        $whereClauses += $Filter
    }
    
    if ($whereClauses.Count -gt 0) {
        $params['WHERE'] = ($whereClauses -join ' AND ')
    }
    
    if ($Limit) {
        $params['LIMIT'] = $Limit.ToString()
    }
    
    try {
        $result = Invoke-EfficientIPAPI -Config $Config -Service "ip_address_list" -Parameters $params
        
        if ($result) {
            return $result
        }
        else {
            return @()
        }
    }
    catch {
        Write-Error "Failed to retrieve IP addresses: $($_.Exception.Message)"
        throw
    }
}

#endregion

#region VLAN-Specific Functions

function Get-VLAN40Devices {
    <#
    .SYNOPSIS
        Get all devices in VLAN 40 subnets
    
    .EXAMPLE
        $devices = Get-VLAN40Devices -Config $config
        $devices | Export-Csv -Path "VLAN40_Devices.csv" -NoTypeInformation
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,
        
        [Parameter(Mandatory=$false)]
        [string]$VLANPattern = "*40*"
    )
    
    Write-Host "Searching for VLAN 40 subnets..." -ForegroundColor Yellow
    
    # Get all subnets first
    $allSubnets = Get-EfficientIPSubnet -Config $Config
    
    # Filter for VLAN 40 - adjust pattern as needed
    $vlan40Subnets = $allSubnets | Where-Object {
        $_.subnet_name -like $VLANPattern -or
        $_.subnet_class_name -like $VLANPattern
    }
    
    if ($vlan40Subnets.Count -eq 0) {
        Write-Warning "No VLAN 40 subnets found. Trying alternative filters..."
        
        # Try direct API filter
        $vlan40Subnets = Get-EfficientIPSubnet -Config $Config -Filter "subnet_name like '%40%'"
        
        if ($vlan40Subnets.Count -eq 0) {
            Write-Error "No VLAN 40 subnets found. Please verify subnet naming convention."
            return @()
        }
    }
    
    Write-Host "Found $($vlan40Subnets.Count) VLAN 40 subnets" -ForegroundColor Green
    
    # Get all devices from VLAN 40 subnets
    $allDevices = @()
    $progressCount = 0
    
    foreach ($subnet in $vlan40Subnets) {
        $progressCount++
        Write-Progress -Activity "Retrieving VLAN 40 Devices" `
                       -Status "Processing subnet $progressCount of $($vlan40Subnets.Count): $($subnet.subnet_name)" `
                       -PercentComplete (($progressCount / $vlan40Subnets.Count) * 100)
        
        $addresses = Get-EfficientIPAddress -Config $Config -SubnetId $subnet.subnet_id
        
        foreach ($addr in $addresses) {
            $device = [PSCustomObject]@{
                NAME = if ($addr.ip_name) { $addr.ip_name } else { "" }
                IP = Format-IPFromAPI -IPValue $addr.ip_addr
                MAC = Format-MACFromAPI -MACValue $addr.mac_addr
                SubnetName = $subnet.subnet_name
                SubnetAddress = Format-IPFromAPI -IPValue $subnet.subnet_addr
                SubnetSize = $subnet.subnet_size
                DeviceType = $addr.ip_class_name
                LastSeen = if ($addr.ip_last_seen) { 
                    [datetime]::Parse($addr.ip_last_seen) 
                } else { 
                    $null 
                }
            }
            $allDevices += $device
        }
    }
    
    Write-Progress -Activity "Retrieving VLAN 40 Devices" -Completed
    Write-Host "Retrieved $($allDevices.Count) devices from VLAN 40 subnets" -ForegroundColor Green
    
    return $allDevices
}

#endregion

#region Formatting Functions

function Format-IPFromAPI {
    <#
    .SYNOPSIS
        Format IP address from EfficientIP API response
    #>
    param([string]$IPValue)
    
    if ([string]::IsNullOrEmpty($IPValue)) {
        return ""
    }
    
    # Handle dotted decimal format
    if ($IPValue -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        return $IPValue
    }
    
    # Handle integer format
    if ($IPValue -match '^\d+$') {
        try {
            [uint32]$ipInt = $IPValue
            $byte1 = ($ipInt -shr 24) -band 0xFF
            $byte2 = ($ipInt -shr 16) -band 0xFF
            $byte3 = ($ipInt -shr 8) -band 0xFF
            $byte4 = $ipInt -band 0xFF
            return "$byte1.$byte2.$byte3.$byte4"
        }
        catch {
            return $IPValue
        }
    }
    
    return $IPValue
}

function Format-MACFromAPI {
    <#
    .SYNOPSIS
        Format MAC address from EfficientIP API response
    #>
    param([string]$MACValue)
    
    if ([string]::IsNullOrEmpty($MACValue)) {
        return ""
    }
    
    # Remove separators
    $mac = $MACValue -replace '[:\-\.\s]', ''
    
    # Format as XX:XX:XX:XX:XX:XX
    if ($mac.Length -eq 12) {
        return ($mac -replace '(.{2})(?=.)', '${1}:')
    }
    
    return $MACValue
}

#endregion

#region Export Functions

function Export-VLAN40Report {
    <#
    .SYNOPSIS
        Generate comprehensive VLAN 40 report
    
    .EXAMPLE
        Export-VLAN40Report -Config $config -OutputPath "C:\Reports"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = $PSScriptRoot,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeEmpty
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    # Get devices
    Write-Host "`nGenerating VLAN 40 Report..." -ForegroundColor Cyan
    $devices = Get-VLAN40Devices -Config $Config
    
    if (-not $IncludeEmpty) {
        $devices = $devices | Where-Object { $_.NAME -or $_.MAC }
    }
    
    # Export main device list
    $deviceFile = Join-Path $OutputPath "VLAN40_Devices_$timestamp.csv"
    $devices | Select-Object NAME, IP, MAC, SubnetName, SubnetAddress, DeviceType, LastSeen |
        Export-Csv -Path $deviceFile -NoTypeInformation
    Write-Host "[OK] Device list exported to: $deviceFile" -ForegroundColor Green
    
    # Generate summary
    $summaryFile = Join-Path $OutputPath "VLAN40_Summary_$timestamp.txt"
    $summary = @"
EfficientIP VLAN 40 Report
Generated: $(Get-Date -Format "yyyy-MM-DD HH:mm:ss")
Server: $($Config.Server)

=== Summary Statistics ===
Total Devices: $($devices.Count)
Devices with Names: $(($devices | Where-Object { $_.NAME }).Count)
Devices with MAC Addresses: $(($devices | Where-Object { $_.MAC }).Count)
Unique Subnets: $(($devices | Select-Object -Unique SubnetName).Count)

=== Subnet Breakdown ===
$($devices | Group-Object SubnetName | Sort-Object Count -Descending | ForEach-Object {
    "  $($_.Name): $($_.Count) devices"
} | Out-String)

=== Device Types ===
$($devices | Where-Object { $_.DeviceType } | Group-Object DeviceType | Sort-Object Count -Descending | ForEach-Object {
    "  $($_.Name): $($_.Count) devices"
} | Out-String)
"@
    
    $summary | Out-File -FilePath $summaryFile -Encoding UTF8
    Write-Host "[OK] Summary exported to: $summaryFile" -ForegroundColor Green
    
    # Display summary
    Write-Host "`n$summary" -ForegroundColor White
}

#endregion

#region IP Address Lookup Function

function Get-EfficientIPByHostname {
    <#
    .SYNOPSIS
        Retrieves IP address information from EfficientIP by hostname.
    
    .DESCRIPTION
        Searches EfficientIP IPAM for IP address records matching the specified hostname.
        Returns detailed information including IP address (both decimal and hex), MAC address,
        subnet information, and DHCP lease details.
    
    .PARAMETER Config
        The EfficientIP configuration object (from Connect-EfficientIP)
    
    .PARAMETER Hostname
        The hostname to search for (supports partial matches)
    
    .PARAMETER ExactMatch
        If specified, only returns exact hostname matches
    
    .EXAMPLE
        Get-EfficientIPByHostname -Config $Config -Hostname "PENFL2P16.ohdc.com"
        Returns full details for the specified host
    
    .EXAMPLE
        Get-EfficientIPByHostname -Config $Config -Hostname "PENFL2P16" | 
            Select-Object IPAddress, IPAddressHex, name, mac_addr
        Returns selected properties for hosts matching the partial name
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Config,
        
        [Parameter(Mandatory=$true)]
        [string]$Hostname,
        
        [Parameter(Mandatory=$false)]
        [switch]$ExactMatch
    )
    
    try {
        Write-Verbose "Searching for hostname: $Hostname"
        
        # Try exact match first
        $whereClause = if ($ExactMatch) {
            "name='$Hostname'"
        } else {
            "name='$Hostname'"
        }
        
        $results = Invoke-EfficientIPAPI -Config $Config `
            -Service "ip_address_list" `
            -Method "Get" `
            -Parameters @{
                WHERE = $whereClause
            }
        
        # PowerShell single object vs array fix: use @() to force array
        $resultsArray = @($results)
        
        if ($resultsArray.Count -gt 0 -and $resultsArray[0]) {
            Write-Verbose "Found $($resultsArray.Count) result(s) for exact match"
        }
        elseif (-not $ExactMatch) {
            # If no exact match and not requiring exact, try LIKE search
            Write-Verbose "No exact match found, trying LIKE search"
            $results = Invoke-EfficientIPAPI -Config $Config `
                -Service "ip_address_list" `
                -Method "Get" `
                -Parameters @{
                    WHERE = "name LIKE '%$Hostname%'"
                }
            
            $resultsArray = @($results)
            
            if ($resultsArray.Count -gt 0 -and $resultsArray[0]) {
                Write-Verbose "Found $($resultsArray.Count) result(s) for LIKE search"
            }
        }
        
        if ($resultsArray.Count -gt 0 -and $resultsArray[0]) {
            # Convert hex IP to readable format and add both formats
            foreach ($result in $resultsArray) {
                if ($result) {
                    $hexIP = $result.ip_addr
                    if ($hexIP -match '^([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$') {
                        $readableIP = "$([convert]::ToInt32($matches[1], 16)).$([convert]::ToInt32($matches[2], 16)).$([convert]::ToInt32($matches[3], 16)).$([convert]::ToInt32($matches[4], 16))"
                        $result | Add-Member -NotePropertyName 'IPAddress' -NotePropertyValue $readableIP -Force
                        $result | Add-Member -NotePropertyName 'IPAddressHex' -NotePropertyValue $hexIP -Force
                    }
                }
            }
            
            return $resultsArray
        }
        
        Write-Warning "No results found for hostname: $Hostname"
        return $null
        
    } catch {
        Write-Error "Failed to query EfficientIP: $_"
        throw
    }
}

function Get-EfficientIPByIP {
    <#
    .SYNOPSIS
        Retrieves IP address information from EfficientIP by IP address.
    
    .DESCRIPTION
        Searches EfficientIP IPAM for a specific IP address record.
        Accepts IP addresses in either standard dotted-decimal format or hexadecimal format.
        Returns detailed information including hostname, MAC address, subnet, and DHCP details.
    
    .PARAMETER Config
        The EfficientIP configuration object (from Connect-EfficientIP)
    
    .PARAMETER IPAddress
        The IP address to search for (e.g., "10.215.187.116" or "0ad7bb74")
    
    .EXAMPLE
        Get-EfficientIPByIP -Config $Config -IPAddress "10.215.187.116"
        Returns details for the specified IP address
    
    .EXAMPLE
        Get-EfficientIPByIP -Config $Config -IPAddress "0ad7bb74"
        Returns details using hexadecimal format
    
    .EXAMPLE
        "10.215.187.116" | Get-EfficientIPByIP -Config $Config | 
            Select-Object IPAddress, IPAddressHex, name, mac_addr, subnet_name
        Returns selected properties via pipeline
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Config,
        
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$IPAddress
    )
    
    process {
        try {
            # Determine if input is hex or decimal format
            $hexIP = if ($IPAddress -match '^[0-9a-fA-F]{8}$') {
                # Already in hex format
                Write-Verbose "Input is in hex format: $IPAddress"
                $IPAddress.ToLower()
            }
            elseif ($IPAddress -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                # Decimal format, convert to hex
                Write-Verbose "Converting decimal IP to hex: $IPAddress"
                Convert-IPToHex -IPAddress $IPAddress
            }
            else {
                throw "Invalid IP address format. Expected dotted-decimal (e.g., 10.215.187.116) or hex (e.g., 0ad7bb74)"
            }
            
            Write-Verbose "Searching for IP (hex): $hexIP"
            
            # Use exact match with proper spacing
            $results = Invoke-EfficientIPAPI -Config $Config `
                -Service "ip_address_list" `
                -Method "Get" `
                -Parameters @{
                    WHERE = "ip_addr = '$hexIP'"
                    limit = 10
                }
            
            # PowerShell single object vs array fix: use @() to force array
            $resultsArray = @($results)
            
            if ($resultsArray.Count -gt 0 -and $resultsArray[0]) {
                Write-Verbose "Found $($resultsArray.Count) result(s)"
                
                # Add readable IP to all results
                foreach ($result in $resultsArray) {
                    if ($result -and $result.ip_addr) {
                        $readableIP = Convert-HexToIP -HexAddress $result.ip_addr
                        $result | Add-Member -NotePropertyName 'IPAddress' -NotePropertyValue $readableIP -Force
                        $result | Add-Member -NotePropertyName 'IPAddressHex' -NotePropertyValue $result.ip_addr -Force
                    }
                }
                
                return $resultsArray
            }
            
            Write-Warning "No results found for IP address: $IPAddress ($hexIP)"
            return $null
            
        } catch {
            Write-Error "Failed to query EfficientIP: $_"
            throw
        }
    }
}

function Get-IPAddressInfo {
    <#
    .SYNOPSIS
        Get comprehensive IP address information from EfficientIP
    
    .DESCRIPTION
        Looks up an IP address and returns detailed information including:
        - IP Address, Subnet Address, Subnet Name
        - DNS Name, DNS IP Address
        - DHCP MAC Address, IPAM MAC Address
        - Device Type, Last Seen, IDs
    
    .PARAMETER Config
        EfficientIP configuration object from Connect-EfficientIP
    
    .PARAMETER IPAddress
        The IP address to look up (e.g., "192.168.40.10" or "10.215.187.116")
    
    .PARAMETER Quiet
        Suppress console output and only return the object
    
    .EXAMPLE
        $config = Connect-EfficientIP -Server "RICTX-IPAM-P01.ohdc.com" -Credential $cred -IgnoreSSL
        Get-IPAddressInfo -Config $config -IPAddress "10.215.187.116"
    
    .EXAMPLE
        # Look up multiple IPs
        $ips = @("10.215.187.116", "10.215.187.117")
        $results = $ips | ForEach-Object { Get-IPAddressInfo -Config $config -IPAddress $_ -Quiet }
        $results | Format-Table
    
    .EXAMPLE
        # Export to CSV
        $results = Get-IPAddressInfo -Config $config -IPAddress "10.215.187.116"
        $results | Export-Csv "C:\Temp\IP_Info.csv" -NoTypeInformation
    
    .NOTES
        Author: Michael David George
        Date: 2025-01-21
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,
        
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('IP', 'Address')]
        [string]$IPAddress,
        
        [Parameter(Mandatory=$false)]
        [switch]$Quiet
    )
    
    begin {
        Write-Verbose "Starting IP address lookup..."
    }
    
    process {
        if (-not $Quiet) {
            Write-Host "`nLooking up IP: $IPAddress" -ForegroundColor Cyan
        }
        
        try {
            # Query for the IP address
            $ipFilter = "ip_addr='$IPAddress'"
            Write-Verbose "Filter: $ipFilter"
            
            $ipResult = Invoke-EfficientIPAPI -Config $Config `
                                              -Service "ip_address_list" `
                                              -Parameters @{ WHERE = $ipFilter }
            
            if (-not $ipResult -or $ipResult.Count -eq 0) {
                Write-Warning "IP address $IPAddress not found in IPAM"
                return $null
            }
            
            # Get the first result (should only be one)
            $ipInfo = $ipResult[0]
            
            # Get subnet information
            $subnetInfo = $null
            if ($ipInfo.subnet_id) {
                Write-Verbose "Getting subnet info for subnet_id: $($ipInfo.subnet_id)"
                $subnetResult = Invoke-EfficientIPAPI -Config $Config `
                                                      -Service "ip_subnet_info" `
                                                      -Parameters @{ subnet_id = $ipInfo.subnet_id }
                if ($subnetResult) {
                    $subnetInfo = $subnetResult[0]
                }
            }
            
            # Format the output
            $result = [PSCustomObject]@{
                'IP Address' = Format-IPFromAPI -IPValue $ipInfo.ip_addr
                'Subnet Address' = if ($subnetInfo) { Format-IPFromAPI -IPValue $subnetInfo.subnet_addr } else { "" }
                'Subnet Name' = if ($subnetInfo) { $subnetInfo.subnet_name } else { "" }
                'DNS Name' = if ($ipInfo.ip_name) { $ipInfo.ip_name } else { "" }
                'DNS IP Address' = Format-IPFromAPI -IPValue $ipInfo.ip_addr
                'DHCP MAC Address' = Format-MACFromAPI -MACValue $ipInfo.mac_addr
                'IPAM MAC Address' = Format-MACFromAPI -MACValue $ipInfo.mac_addr
                'Device Type' = if ($ipInfo.ip_class_name) { $ipInfo.ip_class_name } else { "" }
                'Last Seen' = if ($ipInfo.ip_last_seen) { $ipInfo.ip_last_seen } else { "" }
                'Subnet ID' = if ($ipInfo.subnet_id) { $ipInfo.subnet_id } else { "" }
                'IP ID' = if ($ipInfo.ip_id) { $ipInfo.ip_id } else { "" }
            }
            
            # Display the result if not quiet
            if (-not $Quiet) {
                Write-Host "`nIP Address Details:" -ForegroundColor Green
                $result | Format-List
            }
            
            return $result
        }
        catch {
            Write-Error "Failed to look up IP address $IPAddress : $($_.Exception.Message)"
            return $null
        }
    }
    
    end {
        Write-Verbose "IP address lookup complete"
    }
}

function Update-EfficientIPDNS {
    <#
    .SYNOPSIS
        Updates DNS A record for a server during datacenter failover
    
    .DESCRIPTION
        Updates the DNS A record in EfficientIP SOLIDserver when a server 
        fails over from one datacenter to another. Includes validation, 
        logging, and rollback capabilities.

        Requirements

        Input Parameters:

        Server hostname (e.g., "RICTX-SQL-P01.ohdc.com")
        New IP address after failover (e.g., "10.200.50.100")
        Optional: Old IP address for validation


        Safety Requirements:

        ✅ Pre-validation: Verify server exists in DNS
        ✅ Backup: Record old IP before changing
        ✅ Logging: Comprehensive audit trail
        ✅ Rollback capability: Ability to revert changes
        ✅ Testing: Extensive testing in dev/staging first
        ✅ Approval workflow: Change control integration


        EfficientIP API Operations Needed:

        Query current DNS A record
        Update DNS A record
        Verify DNS propagation
        Update IPAM IP address allocation




                    Step 1: Research & Documentation (Week 1)

                     Review EfficientIP API documentation for DNS updates
                     Identify required API endpoints and permissions
                     Document current DNS update process
                     Review change control requirements

                    Step 2: Development (Week 2-3)

                     Build read-only validation functions
                     Implement logging framework
                     Create backup/snapshot capability
                     Develop core update function with WhatIf
                     Build rollback function

                    Step 3: Testing (Week 4)

                     Unit testing in dev environment
                     Integration testing with failover scenarios
                     Validate rollback procedures
                     Performance testing
                     Document test results

                    Step 4: Staging Validation (Week 5)

                     Deploy to staging environment
                     Execute controlled failover tests
                     Verify DNS propagation
                     Validate monitoring/alerting

                    Step 5: Production Rollout (Week 6+)

                     Change control approval
                     Deploy to production (read-only first)
                     Pilot with 1-2 non-critical servers
                     Full rollout after successful pilot
                     Create runbook and training materials

                    Critical Considerations for Phase 2

                    DNS Zones: Which DNS zones are managed by EfficientIP?
                    Permissions: Do we have API permissions for DNS updates?
                    Integration: How does this integrate with failover automation?
                    Validation: How do we verify DNS propagation was successful?
                    Timing: When in the failover process should DNS be updated?
                    Monitoring: How do we alert if DNS update fails?

                    Questions for Phase 2 Planning

                    What triggers the failover event? (Manual, automated, orchestration tool?)
                    Are there multiple DNS servers that need updating?
                    What's the rollback procedure if failover fails?
                    Are there any dependencies (load balancers, certificates, etc.)?
                    What's the expected RTO/RPO for failover?
                    Who approves DNS changes in production?


    
    .PARAMETER Config
        EfficientIP configuration object
    
    .PARAMETER Hostname
        Fully qualified domain name (e.g., "server01.ohdc.com")
    
    .PARAMETER NewIPAddress
        New IP address after failover
    
    .PARAMETER OldIPAddress
        Optional: Current IP address for validation
    
    .PARAMETER WhatIf
        Shows what would be changed without making changes
    
    .PARAMETER Force
        Skip confirmation prompts (use with caution)
    
    .EXAMPLE
        # Preview change
        Update-EfficientIPDNS -Config $config -Hostname "RICTX-SQL-P01.ohdc.com" -NewIPAddress "10.200.50.100" -WhatIf
    
    .EXAMPLE
        # Execute change with confirmation
        Update-EfficientIPDNS -Config $config -Hostname "RICTX-SQL-P01.ohdc.com" -NewIPAddress "10.200.50.100"
    
    .NOTES
        IMPORTANT: This makes changes to production DNS!
        Always test in dev environment first.
        Requires Change Control approval.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$true)]
        $Config,
        
        [Parameter(Mandatory=$true)]
        [string]$Hostname,
        
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')]
        [string]$NewIPAddress,
        
        [Parameter(Mandatory=$false)]
        [string]$OldIPAddress,
        
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )
    
    # Implementation TBD - Phase 2
}

#endregion

# Export module members
Export-ModuleMember -Function @(
    'Connect-EfficientIP',
    'Invoke-EfficientIPAPI',
    'Get-EfficientIPSubnet',
    'Get-EfficientIPSubnetInfo',
    'Get-EfficientIPAddress',
    'Get-VLAN40Devices',
    'Export-VLAN40Report',
    'Get-IPAddressInfo',
    'Convert-IPToHex',
    'Convert-HexToIP',
    'Get-EfficientIPByHostname',
    'Get-EfficientIPByIP',
    'Show-ConnectEfficientIPHelp'
)



<#
# Test conversion functions
Convert-IPToHex -IPAddress "10.215.187.116"
# Output: 0ad7bb74

Convert-HexToIP -HexAddress "0ad7bb74"
# Output: 10.215.187.116

# Pipeline examples
"192.168.1.1" | Convert-IPToHex
# Output: c0a80101

"c0a80101" | Convert-HexToIP
# Output: 192.168.1.1

# Test lookup by hostname
Get-EfficientIPByHostname -Config $Config -Hostname "PENFL2P16.ohdc.com" |
    Select-Object IPAddress, IPAddressHex, name, mac_addr, subnet_name

# Test lookup by IP (decimal)
Get-EfficientIPByIP -Config $Config -IPAddress "10.215.187.116" |
    Select-Object IPAddress, IPAddressHex, name, mac_addr

# Test lookup by IP (hex)
Get-EfficientIPByIP -Config $Config -IPAddress "0ad7bb74" |
    Select-Object IPAddress, IPAddressHex, name, mac_addr

# Pipeline example
"10.215.187.116" | Get-EfficientIPByIP -Config $Config |
    Format-Table IPAddress, IPAddressHex, name, mac_addr, subnet_name
#>