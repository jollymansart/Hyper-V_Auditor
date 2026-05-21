@{
    # Script module or binary module file associated with this manifest
    RootModule = 'EfficientIP-Module.psm1'
    
    # Version number of this module
    ModuleVersion = '3.10.12'
    
    # Supported PSEditions
    CompatiblePSEditions = @('Desktop', 'Core')
    
    # ID used to uniquely identify this module
    GUID = 'b2c3d4e5-f6a7-48b9-c0d1-e2f3a4b5c6d7'
    
    # Author of this module
    Author = 'Michael David George'
    
    # Company or vendor of this module
    CompanyName = 'Overhead Door Corporation'
    
    # Copyright statement for this module
    Copyright = '(c) 2025 Overhead Door Corporation. All rights reserved.'
    
    # Description of the functionality provided by this module
    Description = 'Advanced EfficientIP SOLIDserver API PowerShell Module. Comprehensive module for interacting with EfficientIP SOLIDserver REST API. Provides functions for subnet discovery, device enumeration, IPAM data retrieval, and VLAN filtering. Main Functions: Connect-EfficientIP (Establish authenticated session with SOLIDserver), Get-EfficientIPByIP (Retrieve device information by IP address), Get-EfficientIPByHostname (Retrieve device information by hostname), Get-EfficientIPSubnets (List subnets with filtering), Get-EfficientIPDevices (Enumerate devices with advanced queries). Features: REST API integration with EfficientIP SOLIDserver, Secure credential management, SSL/TLS support with certificate validation override, WHERE clause filtering, ORDERBY clause sorting, Comprehensive error handling, PowerShell 5.1 and 7+ compatible, Detailed verbose logging, Session state management. API Services Supported: ip_address_list, ip_address_info, ip_subnet_list, ip_site_list, Various *_count *_add *_delete operations. Authentication: Credential-based authentication, Session token management, SSL certificate validation control.'
    
    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'
    
    # Minimum version of Microsoft .NET Framework required by this module
    DotNetFrameworkVersion = '4.7.2'
    
    # Functions to export from this module
    FunctionsToExport = @(
        'Connect-EfficientIP',
        'Get-EfficientIPByIP',
        'Get-EfficientIPByHostname',
        'Get-EfficientIPSubnets',
        'Get-EfficientIPDevices',
        'Set-EfficientIPCredential',
        'Get-EfficientIPCredential',
        'Remove-EfficientIPCredential',
        'Show-ConnectEfficientIPHelp'
    )
    
    # Cmdlets to export from this module
    CmdletsToExport = @()
    
    # Variables to export from this module
    VariablesToExport = @()
    
    # Aliases to export from this module
    AliasesToExport = @()
    
    # List of all files packaged with this module
    FileList = @(
        'EfficientIP-Module_v1_1_5.psm1',
        'EfficientIP-Module.psd1'
    )
    
    # Private data to pass to the module
    PrivateData = @{
        PSData = @{
            # Tags for module discovery
            Tags = @(
                'IPAM',
                'EfficientIP',
                'SOLIDserver',
                'NetworkManagement',
                'IPAddressManagement',
                'DNS',
                'DHCP',
                'AssetManagement'
            )
            
            # Release notes
            ReleaseNotes = @'
Version 1.1.5 (2025-01-21)
- ENHANCEMENT: Improved error handling for API timeouts
- ENHANCEMENT: Better verbose logging
- ENHANCEMENT: Credential management functions
- FIX: SSL certificate validation handling
- FIX: Session timeout management

Version 1.1.4 (2025-01-15)
- NEW: Get-EfficientIPByHostname function
- ENHANCEMENT: WHERE clause support
- ENHANCEMENT: ORDERBY clause support

Version 1.1.3 (2025-01-10)
- NEW: Subnet filtering capabilities
- NEW: Device enumeration
- ENHANCEMENT: Improved error messages

Version 1.1.0 (2024-12-20)
- Initial release with core IPAM functionality
- Connect-EfficientIP for authentication
- Get-EfficientIPByIP for device lookup
- REST API integration
'@
        }
    }
}
