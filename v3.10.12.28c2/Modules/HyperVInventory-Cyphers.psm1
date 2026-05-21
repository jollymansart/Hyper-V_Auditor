<#
.SYNOPSIS
    HyperVInventory-Cyphers.psm1
    Cipher / Kerberos Encryption Type audit module for the Hyper-V Inventory Suite.

.DESCRIPTION
    Adds five worksheets to the report, answering the questions Michael raised
    after the v3.10.12.26 run:

      Cipher-Audit       One row per machine (every Hyper-V host AND every
                         Windows VM, including domain controllers). Runtime
                         SChannel protocol state, GPO cipher policy, the
                         actual negotiable TLS cipher-suite list, weak/critical
                         cipher flags, and the local Kerberos SupportedEncryptionTypes
                         registry value.

      Kerberos-Etypes    One row per machine. The result of
                         Get-ADComputer <server> -Properties msDS-SupportedEncryptionTypes,
                         the raw integer DECODED into its category (matching the
                         0 / 4 / 8 / 16 / 24 / 28 table), and the exact Kerberos
                         encryption algorithms (etypes) each category enables.

      Cipher-Interop     The negotiable cipher suites and Kerberos etypes that
                         are common to ALL machines of the same OS version
                         (one group per OS, domain controllers broken out as
                         their own group). This is the "what works everywhere"
                         interoperability floor, plus a cross-fleet lowest
                         common denominator row.

      Cipher-Diagnostics Findings explaining why domain controllers cannot
                         update / verify domain trusts, why Netlogon secure
                         channels fail, and why SMB file shares stop working --
                         all of which trace back to Kerberos etype negotiation
                         (KDC_ERR_ETYPE_NOTSUPP) caused by msDS-SupportedEncryptionTypes
                         mismatches.

      Etype-Reference    A static educational tab: the encryption-type value
                         table and the etype-to-cipher correlation, so the
                         report is self-documenting.

    Runs as a post-processing step after host + VM collection is complete.
    The runtime cipher portion uses WinRM (with a PowerShell Direct fallback
    through the Hyper-V host). The Kerberos etype portion is pure AD LDAP and
    therefore covers every machine -- including VMs that are powered off or
    WinRM-unreachable, and including DCs.

.NOTES
    Author   : Michael George
    Company  : Overhead Door Corporation / Delzron
    Version  : 3.10.12.27
    PS Compat: 5.1 -- ASCII-only string literals, no non-ASCII characters.

    VM-SCOPE BUG NOTE (read before maintaining this file):
    The HyperVInventory-TLS and HyperVInventory-Permissions modules skip every
    VM because they test  $vm.State -ne 'Running'  -- but the VM objects built
    in HyperVInventory-Core expose the power state as  $vm.Powerstate  with the
    values 'poweredOn' / 'poweredOff'. There is no .State property, so the test
    is always true and every VM is skipped. THIS MODULE deliberately tests
    $vm.Powerstate and resolves the real guest hostname (GuestComputerName ->
    AD_ComputerName -> KVP FQDN -> display name) instead of the Hyper-V display
    name, so the VM scope actually works here.
#>

#Requires -Version 5.0

# =====================================================================
# STATIC REFERENCE DATA
# =====================================================================

function Get-CipherEtypeReferenceData {
    <#
    .SYNOPSIS
        Returns the static reference rows for the Etype-Reference worksheet.
        No parameters, no side effects -- safe to call standalone.
    #>
    [CmdletBinding()]
    param()

    $rows = [System.Collections.Generic.List[object]]::new()

    # --- Section 1: msDS-SupportedEncryptionTypes value table -----------
    $valTable = @(
        @{ V='0';  Cat='Default (RC4 allowed)';        Krb='RC4-HMAC (etype 23) by OS default; AES128/AES256 also offered on 2008+';                                Note='Attribute not configured. The Kerberos client falls back to the OS default set. On Server 2008+ that effectively allows RC4 + AES. Treated as RC4-permissive for trust planning.' }
        @{ V='4';  Cat='RC4_HMAC';                     Krb='RC4-HMAC-MD5 (etype 23) ONLY';                                                                            Note='AES is NOT offered by this account. Any partner that has disabled RC4 cannot complete Kerberos with it. Common cause of trust / secure-channel failure.' }
        @{ V='8';  Cat='AES128';                       Krb='AES128-CTS-HMAC-SHA1-96 (etype 17) ONLY';                                                                 Note='RC4 is NOT offered. A partner that only supports RC4 (value 4) or DES cannot negotiate with this account.' }
        @{ V='16'; Cat='AES256';                       Krb='AES256-CTS-HMAC-SHA1-96 (etype 18) ONLY';                                                                 Note='RC4 and AES128 are NOT offered. Strongest single setting, but the least interoperable -- both ends must support AES256.' }
        @{ V='24'; Cat='AES128 + AES256';              Krb='AES128 (etype 17) + AES256 (etype 18). RC4 NOT offered.';                                                 Note='Recommended modern value once RC4 is no longer required anywhere. AES-only -- verify every trust partner and member server supports AES first.' }
        @{ V='28'; Cat='RC4 + AES128 + AES256';        Krb='RC4-HMAC (23) + AES128 (17) + AES256 (18)';                                                               Note='Most interoperable. Negotiates AES when both ends support it, falls back to RC4 otherwise. Safe transitional value while migrating a domain off RC4.' }
        @{ V='3';  Cat='DES-CBC-CRC + DES-CBC-MD5';    Krb='DES-CBC-CRC (etype 1) + DES-CBC-MD5 (etype 3)';                                                           Note='DES only. Broken and disabled by default since Server 2008 R2. A DES-only trust object is a classic "trust cannot be updated" cause.' }
        @{ V='31'; Cat='DES + RC4 + AES128 + AES256';  Krb='DES (1,3) + RC4 (23) + AES128 (17) + AES256 (18)';                                                        Note='Everything including DES. Seen on very old accounts. Strip the DES bits (subtract 3) to reach value 28.' }
    )
    foreach ($e in $valTable) {
        $rows.Add([PSCustomObject]@{
            Section            = '1. Encryption Type Values (msDS-SupportedEncryptionTypes)'
            Value              = $e.V
            EncryptionCategory = $e.Cat
            KerberosCiphers    = $e.Krb
            Meaning            = $e.Note
        })
    }

    # --- Section 2: individual bit meanings -----------------------------
    $bitTable = @(
        @{ V='0x01 (1)';   Cat='DES-CBC-CRC';                    Krb='etype 1  -- DES-CBC-CRC';                          Note='56-bit DES. Cryptographically broken. Disabled by default since Server 2008 R2.' }
        @{ V='0x02 (2)';   Cat='DES-CBC-MD5';                    Krb='etype 3  -- DES-CBC-MD5';                          Note='56-bit DES. Cryptographically broken. Disabled by default since Server 2008 R2.' }
        @{ V='0x04 (4)';   Cat='RC4-HMAC';                       Krb='etype 23 -- RC4-HMAC-MD5 (ARCFOUR)';               Note='128-bit RC4. Weak; Microsoft is removing it. The interop fallback during AES migration.' }
        @{ V='0x08 (8)';   Cat='AES128-CTS-HMAC-SHA1-96';        Krb='etype 17 -- AES128-CTS-HMAC-SHA1-96';              Note='128-bit AES. Strong. Supported Server 2008 and later.' }
        @{ V='0x10 (16)';  Cat='AES256-CTS-HMAC-SHA1-96';        Krb='etype 18 -- AES256-CTS-HMAC-SHA1-96';              Note='256-bit AES. Strongest standard etype. Supported Server 2008 and later.' }
        @{ V='0x20 (32)';  Cat='AES256-CTS-HMAC-SHA1-96-SK';     Krb='AES256 session-key marker / future-use bit';        Note='Reserved / session-key variant. Rarely set on its own. Leave it alone unless Microsoft guidance says otherwise.' }
    )
    foreach ($e in $bitTable) {
        $rows.Add([PSCustomObject]@{
            Section            = '2. Individual Bit Meanings (add bits to build a value)'
            Value              = $e.V
            EncryptionCategory = $e.Cat
            KerberosCiphers    = $e.Krb
            Meaning            = $e.Note
        })
    }

    # --- Section 3: how this connects to trust / SMB failures -----------
    $explain = @(
        @{ T='How the KDC picks an etype'; D='When a client requests a Kerberos ticket, the KDC must find an encryption type supported by the CLIENT account, the TARGET account, and the KDC itself (krbtgt). msDS-SupportedEncryptionTypes is that per-account list. If the three sets do not intersect, the KDC returns KRB_AP_ERR_ETYPE_NOSUPP / KDC_ERR_ETYPE_NOTSUPP and ticket issuance fails.' }
        @{ T='Why domain trusts fail to update'; D='A trust is represented by a trustedDomain (TDO) / interdomain trust account. That account has its own msDS-SupportedEncryptionTypes. If one side enforces AES-only and the trust account still advertises RC4 or DES only (or vice versa), trust verification (netdom trust /verify, Test-WindowsTrust, AD Domains and Trusts validate) fails because the referral ticket cannot be encrypted with a mutually supported etype.' }
        @{ T='Why the secure channel breaks'; D='The Netlogon secure channel between a member computer and a DC is itself authenticated with Kerberos. If the computer account and the DC do not share an etype, the computer cannot obtain a TGT or the Netlogon service ticket. Test-ComputerSecureChannel returns False; System log shows Netlogon events 5719, 3210, 5722, 5723.' }
        @{ T='Why SMB file shares stop working'; D='SMB authenticates with Kerberos first. No service ticket for cifs/<server> means access to \\\\server\\share is denied. The client only succeeds if NTLM fallback is still permitted; if NTLM is also restricted, the share is completely unreachable -- even though the network path is fine.' }
        @{ T='The safe migration order'; D='1) Set every account (DCs, members, trust objects) to value 28 (RC4 + AES) so AES is negotiated where possible without breaking RC4-only partners. 2) Confirm zero RC4 Kerberos tickets are still being issued (audit etype 23 in 4768/4769 events). 3) Only then move to value 24 (AES-only). Never jump an isolated DC or trust object straight to AES-only while RC4-only partners remain.' }
        @{ T='Note: Kerberos etypes vs TLS cipher suites'; D='Kerberos encryption types (this attribute) and SCHANNEL TLS/SSL cipher suites are SEPARATE systems. msDS-SupportedEncryptionTypes controls Kerberos only. The Cipher-Audit tab covers TLS/SCHANNEL. Both are reported because both must be healthy for full secure-channel and application connectivity.' }
    )
    foreach ($e in $explain) {
        $rows.Add([PSCustomObject]@{
            Section            = '3. Why etype mismatches break trusts, secure channels and file shares'
            Value              = ''
            EncryptionCategory = $e.T
            KerberosCiphers    = ''
            Meaning            = $e.D
        })
    }

    return $rows
}

# Decode an msDS-SupportedEncryptionTypes integer into category + detail.
function ConvertTo-EtypeDecode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]$Value
    )

    $result = [ordered]@{
        Raw          = ''
        Category     = ''
        DES          = $false
        RC4          = $false
        AES128       = $false
        AES256       = $false
        FutureBits   = $false
        KrbEtypes    = ''
        EtypeNumbers = ''
        IsConfigured = $false
        AESOnly      = $false
        RC4Capable   = $true   # default-permissive
        Weak         = $false
    }

    if ($null -eq $Value -or $Value -eq '' -or $Value -eq '<not set>') {
        $result.Raw          = '<not set>'
        $result.Category     = 'Default (RC4 allowed)'
        $result.KrbEtypes    = 'OS default: RC4-HMAC + AES128 + AES256 on Server 2008+ (RC4 still permitted)'
        $result.EtypeNumbers = '17, 18, 23 (effective)'
        $result.IsConfigured = $false
        $result.RC4Capable   = $true
        return [PSCustomObject]$result
    }

    $intVal = 0
    try { $intVal = [int]$Value } catch { $intVal = -1 }

    if ($intVal -lt 0) {
        $result.Raw      = "$Value"
        $result.Category = 'Unreadable value'
        return [PSCustomObject]$result
    }

    $result.Raw          = "$intVal"
    $result.IsConfigured = $true
    $result.DES          = (($intVal -band 1) -ne 0) -or (($intVal -band 2) -ne 0)
    $result.RC4          = (($intVal -band 4) -ne 0)
    $result.AES128       = (($intVal -band 8) -ne 0)
    $result.AES256       = (($intVal -band 16) -ne 0)
    $result.FutureBits   = (($intVal -band 32) -ne 0)

    $etNames = [System.Collections.Generic.List[string]]::new()
    $etNums  = [System.Collections.Generic.List[string]]::new()
    if (($intVal -band 1)  -ne 0) { $etNames.Add('DES-CBC-CRC');                $etNums.Add('1')  }
    if (($intVal -band 2)  -ne 0) { $etNames.Add('DES-CBC-MD5');                $etNums.Add('3')  }
    if (($intVal -band 4)  -ne 0) { $etNames.Add('RC4-HMAC');                   $etNums.Add('23') }
    if (($intVal -band 8)  -ne 0) { $etNames.Add('AES128-CTS-HMAC-SHA1-96');    $etNums.Add('17') }
    if (($intVal -band 16) -ne 0) { $etNames.Add('AES256-CTS-HMAC-SHA1-96');    $etNums.Add('18') }
    if (($intVal -band 32) -ne 0) { $etNames.Add('AES256-SK (future)');         $etNums.Add('-')  }

    $result.KrbEtypes    = if ($etNames.Count -gt 0) { $etNames -join ', ' } else { 'None enabled (value resolves to no usable etype)' }
    $result.EtypeNumbers = if ($etNums.Count -gt 0) { $etNums -join ', ' } else { '' }
    $result.RC4Capable   = $result.RC4
    $result.AESOnly      = (($result.AES128 -or $result.AES256) -and -not $result.RC4 -and -not $result.DES)
    $result.Weak         = ($result.DES -or (-not $result.AES128 -and -not $result.AES256))

    # Friendly category, matching the published value table where possible.
    $maskNoFuture = $intVal -band 31
    switch ($maskNoFuture) {
        0  { $result.Category = 'No etypes set (value 0 with only future bits)' }
        3  { $result.Category = 'DES only (DES-CBC-CRC + DES-CBC-MD5)' }
        4  { $result.Category = 'RC4_HMAC' }
        8  { $result.Category = 'AES128' }
        16 { $result.Category = 'AES256' }
        24 { $result.Category = 'AES128 + AES256' }
        28 { $result.Category = 'RC4 + AES128 + AES256' }
        31 { $result.Category = 'DES + RC4 + AES128 + AES256' }
        12 { $result.Category = 'RC4 + AES128' }
        20 { $result.Category = 'RC4 + AES256' }
        default {
            $parts = [System.Collections.Generic.List[string]]::new()
            if ($result.DES)    { $parts.Add('DES') }
            if ($result.RC4)    { $parts.Add('RC4') }
            if ($result.AES128) { $parts.Add('AES128') }
            if ($result.AES256) { $parts.Add('AES256') }
            $result.Category = if ($parts.Count -gt 0) { $parts -join ' + ' } else { "Custom (raw $intVal)" }
        }
    }

    return [PSCustomObject]$result
}


# =====================================================================
# MAIN AUDIT FUNCTION
# =====================================================================

function Invoke-CipherEncryptionAudit {
    <#
    .SYNOPSIS
        Runs the cipher + Kerberos encryption-type audit across every host and
        every Windows VM, and returns the data for the five worksheets.

    .PARAMETER HostData
        Array of completed host objects from the main inventory (each host has
        a .VMs collection).

    .PARAMETER Credential
        Primary WinRM / AD credential.

    .PARAMETER DomainCredentials
        Hashtable of per-domain credentials for multi-domain environments
        (keys are lowercase domain names).

    .PARAMETER IncludeVMs
        If $true (default) the runtime cipher portion also reaches into every
        running Windows VM. The Kerberos etype portion always covers VMs
        because it is AD-only and needs no guest connectivity.

    .PARAMETER ADDomains
        Optional list of AD DNS domain names to query for computer objects and
        domain controllers. If empty, the domains are inferred from the host
        and VM data.

    .OUTPUTS
        Hashtable with keys:
          CipherAudit       [List] one row per machine -- runtime SCHANNEL/cipher state
          KerberosEtypes    [List] one row per machine -- decoded msDS-SupportedEncryptionTypes
          CipherInterop     [List] one row per OS-version group + a fleet LCD row
          CipherDiagnostics [List] trust / secure-channel / file-share findings
          EtypeReference    [List] static reference rows
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][array]$HostData,
        [Parameter(Mandatory = $false)][System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $false)][hashtable]$DomainCredentials = @{},
        [Parameter(Mandatory = $false)][bool]$IncludeVMs = $true,
        [Parameter(Mandatory = $false)][string[]]$ADDomains = @()
    )

    $cipherRows = [System.Collections.Generic.List[object]]::new()
    $etypeRows  = [System.Collections.Generic.List[object]]::new()
    $interop    = [System.Collections.Generic.List[object]]::new()
    $diagRows   = [System.Collections.Generic.List[object]]::new()

    $logAvailable = [bool](Get-Command -Name 'Write-HVLog' -ErrorAction SilentlyContinue)
    function Write-CLog {
        param([string]$Message, [string]$Level = 'Info')
        if ($script:CLogAvailable) { Write-HVLog "  $Message" -Level $Level }
        else { Write-Verbose $Message }
    }
    $script:CLogAvailable = $logAvailable

    # -----------------------------------------------------------------
    # Remote scriptblock -- runtime SCHANNEL / cipher / Kerberos collection.
    # Adapted from Get-TLS_and_Cyphers_v2.ps1; returns structured data
    # instead of writing to the host.
    #
    # OPEN-71 (v3.10.12.28): The scriptblock is written to a per-run temp file
    # and passed to Invoke-Command via -FilePath instead of -ScriptBlock.
    # When -ScriptBlock is used, PS 5.1's Start-Transcript captures the entire
    # scriptblock body on every Invoke-Command call (290+ times per run),
    # inflating the log by thousands of lines of source code.
    # -FilePath causes the transcript to record only the file path, not its content.
    # -----------------------------------------------------------------
    $cipherScriptBlock = {
        $r = @{ ComputerName = $env:COMPUTERNAME; Errors = @() }

        function Get-RegVal { param($Path,$Name)
            try { (Get-ItemProperty -Path $Path -ErrorAction Stop).$Name } catch { $null }
        }

        # OS context
        try {
            $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
            $cs = Get-WmiObject -Class Win32_ComputerSystem  -ErrorAction SilentlyContinue
            $r.OSCaption = if ($os) { $os.Caption } else { '' }
            $r.OSVersion = if ($os) { $os.Version } else { '' }
            $r.OSBuild   = if ($os) { $os.BuildNumber } else { '' }
            $r.IsDC      = if ($cs -and $cs.DomainRole -ge 4) { $true } else { $false }
            $r.Domain    = if ($cs) { $cs.Domain } else { '' }
        } catch { $r.Errors += "OS query: $($_.Exception.Message)" }

        # SCHANNEL protocols
        $protoBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
        $protos = 'SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1','TLS 1.2','TLS 1.3'
        $r.Protocols = @{}
        foreach ($p in $protos) {
            $state = @{}
            foreach ($role in 'Client','Server') {
                $path = "$protoBase\$p\$role"
                $en = Get-RegVal $path 'Enabled'
                $db = Get-RegVal $path 'DisabledByDefault'
                $s = 'System Default'
                if     ($en -eq 0)                  { $s = 'Disabled' }
                elseif ($en -ge 1 -and $db -eq 0)   { $s = 'Enabled' }
                elseif ($db -eq 1)                  { $s = 'DisabledByDefault' }
                $state[$role] = $s
            }
            $r.Protocols[$p] = $state
        }

        # GPO-enforced cipher suite ordering
        $gpoPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
        $gpoRaw  = Get-RegVal $gpoPath 'Functions'
        $r.GPOCipherList = if ($gpoRaw) { @($gpoRaw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } else { @() }
        $r.CipherSource  = if ($gpoRaw) { 'GPO' } else { 'OS Default' }

        # Runtime negotiable cipher suites
        $runtime = @()
        try {
            $cs2 = Get-TlsCipherSuite -ErrorAction Stop
            if ($cs2) {
                if ($cs2[0].PSObject.Properties.Name -contains 'Name') {
                    $runtime = @($cs2 | Select-Object -ExpandProperty Name)
                } elseif ($cs2[0].PSObject.Properties.Name -contains 'CipherSuite') {
                    $runtime = @($cs2 | Select-Object -ExpandProperty CipherSuite)
                }
            }
        } catch {
            $localPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002'
            $localRaw  = Get-RegVal $localPath 'Functions'
            if ($localRaw) { $runtime = @($localRaw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
        }
        $r.RuntimeCiphers = @($runtime | Sort-Object -Unique)

        # Explicit SCHANNEL cipher overrides (RC4 128/128, DES, Triple DES, etc.)
        $r.CipherOverrides = @{}
        $cipherBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers'
        if (Test-Path $cipherBase) {
            try {
                Get-ChildItem $cipherBase -ErrorAction SilentlyContinue | ForEach-Object {
                    $en = Get-RegVal $_.PSPath 'Enabled'
                    $st = switch ($en) { 0 { 'Disabled' } { $_ -ge 1 } { 'Enabled' } default { 'Default' } }
                    $r.CipherOverrides[$_.PSChildName] = $st
                }
            } catch { $r.Errors += "Cipher overrides: $($_.Exception.Message)" }
        }

        # Local Kerberos SupportedEncryptionTypes (LSA) -- what the client SSP requests.
        $krbPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'
        $r.LocalKerbEtypes = Get-RegVal $krbPath 'SupportedEncryptionTypes'

        return $r
    }

    # OPEN-71: Write scriptblock to a temp file so Invoke-Command uses -FilePath.
    # PS 5.1 transcript captures -ScriptBlock body on every call; -FilePath logs
    # only the path. One file shared across all Invoke-CipherCheck calls; cleaned
    # up in the finally block wrapping the Phase 1 collection loop.
    $cipherTempScript = $null
    try {
        $cipherTempScript = [System.IO.Path]::Combine(
            [System.IO.Path]::GetTempPath(),
            "HVI_CipherAudit_$([System.Diagnostics.Process]::GetCurrentProcess().Id).ps1"
        )
        Set-Content -Path $cipherTempScript -Value $cipherScriptBlock.ToString() -Encoding UTF8
    }
    catch {
        # Temp file creation failed -- fall back to scriptblock (transcript will be verbose)
        Write-CLog "Cipher Audit: could not create temp script file ($($_.Exception.Message)) -- using scriptblock (log may be verbose)" 'Warning'
        $cipherTempScript = $null
    }

    # -----------------------------------------------------------------
    # Helper: choose the right credential for a domain.
    # -----------------------------------------------------------------
    function Get-CredFor {
        param([string]$Domain,[System.Management.Automation.PSCredential]$Default,[hashtable]$Map)
        if ($Domain -and $Map -and $Map.Count -gt 0) {
            $k = $Domain.ToLower()
            if ($Map.ContainsKey($k)) { return $Map[$k] }
            foreach ($key in $Map.Keys) {
                if ($k -like "*$($key.ToLower())*" -or $key.ToLower() -like "*$k*") { return $Map[$key] }
            }
        }
        return $Default
    }

    # Helper: resolve the real guest hostname (NOT the Hyper-V display name).
    function Resolve-GuestTarget {
        param($VM)
        $cands = @(
            $VM.GuestComputerName
            $VM.AD_ComputerName
            $(if ($VM.KVP -and $VM.KVP['FullyQualifiedDomainName']) { ($VM.KVP['FullyQualifiedDomainName'] -split '\.')[0] } else { $null })
        )
        foreach ($c in $cands) {
            if ($c -and ($c -notmatch '[^\w\-\.]')) { return $c }
        }
        # Last resort: VM display name, but only if it is clean (no spaces / parentheses).
        $dn = if ($VM.VM) { $VM.VM } else { $VM.VMName }
        if ($dn -and ($dn -notmatch '[^\w\-\.]')) { return $dn }
        return $null
    }

    # Helper: classify a raw OS caption into a normalized group key.
    function Get-OSGroupKey {
        param([string]$Caption,[bool]$IsDC)
        $c = if ($Caption) { $Caption } else { 'Unknown OS' }
        $norm = $c
        if     ($c -match '2025')       { $norm = 'Windows Server 2025' }
        elseif ($c -match '2022')       { $norm = 'Windows Server 2022' }
        elseif ($c -match '2019')       { $norm = 'Windows Server 2019' }
        elseif ($c -match '2016')       { $norm = 'Windows Server 2016' }
        elseif ($c -match '2012 R2')    { $norm = 'Windows Server 2012 R2' }
        elseif ($c -match '2012')       { $norm = 'Windows Server 2012' }
        elseif ($c -match '2008 R2')    { $norm = 'Windows Server 2008 R2' }
        elseif ($c -match '2008')       { $norm = 'Windows Server 2008' }
        elseif ($c -match 'Windows 11') { $norm = 'Windows 11 (client)' }
        elseif ($c -match 'Windows 10') { $norm = 'Windows 10 (client)' }
        if ($IsDC) { return "Domain Controllers -- $norm" }
        return $norm
    }

    # Helper: run the cipher scriptblock against one machine, WinRM first,
    # PowerShell Direct through the host as a fallback.
    function Invoke-CipherCheck {
        param(
            [string]$Target,
            [System.Management.Automation.PSCredential]$Cred,
            [string]$HostFQDN,
            [string]$VMDisplayName,
            [System.Management.Automation.PSCredential]$HostCred
        )
        # WinRM -- use -FilePath (temp script) to avoid PS transcript capturing the
        # scriptblock body on every call (OPEN-71). Fall back to -ScriptBlock if
        # temp file creation failed.
        try {
            if ($cipherTempScript -and (Test-Path $cipherTempScript)) {
                $p = @{ ComputerName = $Target; FilePath = $cipherTempScript; ErrorAction = 'Stop' }
            }
            else {
                $p = @{ ComputerName = $Target; ScriptBlock = $cipherScriptBlock; ErrorAction = 'Stop' }
            }
            if ($Cred) { $p['Credential'] = $Cred }
            $raw = Invoke-Command @p
            if ($raw) { $raw.CollectionMethod = 'WinRM'; return $raw }
        } catch {
            $winrmErr = $_.Exception.Message
        }
        # PowerShell Direct fallback (Hyper-V VMs only)
        if ($HostFQDN -and $VMDisplayName) {
            try {
                $pd = {
                    param($VmName,$InnerCred,$Sb)
                    Invoke-Command -VMName $VmName -Credential $InnerCred -ScriptBlock $Sb -ErrorAction Stop
                }
                $hp = @{ ComputerName = $HostFQDN; ScriptBlock = $pd; ArgumentList = @($VMDisplayName,$Cred,$cipherScriptBlock); ErrorAction = 'Stop' }
                if ($HostCred) { $hp['Credential'] = $HostCred }
                $raw = Invoke-Command @hp
                if ($raw) { $raw.CollectionMethod = 'PSDirect'; return $raw }
            } catch {
                return @{ ComputerName = $Target; Error = "WinRM: $winrmErr | PSDirect: $($_.Exception.Message)"; CollectionMethod = 'Failed' }
            }
        }
        return @{ ComputerName = $Target; Error = "WinRM: $winrmErr"; CollectionMethod = 'Failed' }
    }

    # Weak / critical cipher classifiers (string pattern based).
    function Test-WeakCipherName  { param([string]$N) return ($N -match 'RC4|3DES|DES|NULL|MD5|EXPORT|_CBC_') }
    function Test-CritCipherName  { param([string]$N) return ($N -match 'NULL|_RC4_|^RC4|EXPORT|_DES_') }

    # =================================================================
    # PHASE 1 -- runtime cipher collection (hosts + VMs)
    # =================================================================
    Write-CLog "Cipher Audit: starting runtime collection ($($HostData.Count) hosts)"
    $cipherRaw = @{}   # keyed by row identity -> raw result, used by interop + diagnostics

    try {   # OPEN-71: outer try ensures temp script file is cleaned up on any exit path

    foreach ($h in $HostData) {
        if ($h.Error) { continue }
        $hostName = if ($h.HostName) { $h.HostName } elseif ($h.ComputerName) { $h.ComputerName } else { continue }
        $hostFQDN = if ($h.HostFQDN) { $h.HostFQDN } else { $hostName }
        $cluster  = if ($h.ClusterName) { $h.ClusterName } else { '' }
        $hostDom  = if ($h.Domain) { $h.Domain } else { '' }
        $hostCred = if ($h.EffectiveCredential) { $h.EffectiveCredential } else { Get-CredFor -Domain $hostDom -Default $Credential -Map $DomainCredentials }

        $raw = Invoke-CipherCheck -Target $hostFQDN -Cred $hostCred
        $row = New-CipherRow -Raw $raw -MachineName $hostName -MachineType 'Host' -ParentHost '' -Cluster $cluster
        $cipherRows.Add($row)
        $cipherRaw["Host|$hostName"] = @{ Raw = $raw; Row = $row }

        if ($IncludeVMs -and $h.VMs) {
            foreach ($vm in $h.VMs) {
                # CORRECT power-state test -- VM objects use .Powerstate, not .State.
                if ($vm.Powerstate -ne 'poweredOn') { continue }
                $osType = ''
                if ($vm.OSInfo) { $osType = $vm.OSInfo.OSType }
                if (-not $osType) { $osType = $vm.OSType }
                if ($osType -and $osType -notin @('Windows','')) { continue }

                $target = Resolve-GuestTarget -VM $vm
                $display = if ($vm.VM) { $vm.VM } else { $vm.VMName }
                if (-not $target) {
                    # No resolvable hostname -- still emit a row so the gap is visible.
                    $cipherRows.Add( (New-CipherRow -Raw @{ ComputerName = $display; Error = 'No resolvable guest hostname (Hyper-V display name only)'; CollectionMethod = 'Skipped' } -MachineName $display -MachineType 'VM' -ParentHost $hostName -Cluster $cluster) )
                    continue
                }
                $vmDom  = ''
                if ($vm.OSInfo -and $vm.OSInfo.Domain) { $vmDom = $vm.OSInfo.Domain }
                $vmCred = Get-CredFor -Domain $vmDom -Default $Credential -Map $DomainCredentials

                $raw = Invoke-CipherCheck -Target $target -Cred $vmCred -HostFQDN $hostFQDN -VMDisplayName $display -HostCred $hostCred
                $row = New-CipherRow -Raw $raw -MachineName $target -MachineType 'VM' -ParentHost $hostName -Cluster $cluster
                $cipherRows.Add($row)
                $cipherRaw["VM|$target"] = @{ Raw = $raw; Row = $row }
            }
        }
    }
    Write-CLog "Cipher Audit: runtime collection complete -- $($cipherRows.Count) machines"
    }   # end OPEN-71 try block
    finally {
        # Remove the temp script file regardless of success or error
        if ($cipherTempScript -and (Test-Path $cipherTempScript -ErrorAction SilentlyContinue)) {
            Remove-Item $cipherTempScript -Force -ErrorAction SilentlyContinue
        }
    }

    # =================================================================
    # PHASE 2 -- Kerberos etype audit (AD LDAP -- covers every machine + DCs)
    # =================================================================
    $adAvailable = [bool](Get-Command -Name 'Get-ADComputer' -ErrorAction SilentlyContinue)
    if (-not $adAvailable) {
        Write-CLog 'Cipher Audit: ActiveDirectory module not available -- Kerberos-Etypes tab will be limited to local registry values' 'Warning'
    }

    # Build the unique machine list (short names) plus parent-host map.
    $machineIndex = @{}   # shortName -> @{ Type; ParentHost; Cluster; Domain }
    foreach ($h in $HostData) {
        if ($h.Error) { continue }
        $hn = if ($h.HostName) { $h.HostName } elseif ($h.ComputerName) { $h.ComputerName } else { $null }
        if (-not $hn) { continue }
        $short = ($hn -split '\.')[0]
        if (-not $machineIndex.ContainsKey($short)) {
            $machineIndex[$short] = @{ Type='Host'; ParentHost=''; Cluster=$(if($h.ClusterName){$h.ClusterName}else{''}); Domain=$(if($h.Domain){$h.Domain}else{''}) }
        }
        if ($h.VMs) {
            foreach ($vm in $h.VMs) {
                $g = Resolve-GuestTarget -VM $vm
                if (-not $g) { continue }
                $gs = ($g -split '\.')[0]
                if (-not $machineIndex.ContainsKey($gs)) {
                    $vmDom = if ($vm.OSInfo -and $vm.OSInfo.Domain) { $vm.OSInfo.Domain } else { '' }
                    $machineIndex[$gs] = @{ Type='VM'; ParentHost=$hn; Cluster=$(if($h.ClusterName){$h.ClusterName}else{''}); Domain=$vmDom }
                }
            }
        }
    }

    # Determine which AD domains to query.
    $domainSet = New-Object System.Collections.Generic.HashSet[string]
    foreach ($d in $ADDomains)      { if ($d) { [void]$domainSet.Add($d.ToLower()) } }
    foreach ($v in $machineIndex.Values) { if ($v.Domain) { [void]$domainSet.Add($v.Domain.ToLower()) } }
    if ($DomainCredentials) { foreach ($k in $DomainCredentials.Keys) { [void]$domainSet.Add($k.ToLower()) } }

    # Pull every DC explicitly so domain controllers are always covered even
    # though they are VMs (and would otherwise be skipped if WinRM is down).
    $dcShortNames = New-Object System.Collections.Generic.HashSet[string]
    if ($adAvailable) {
        foreach ($dom in $domainSet) {
            try {
                $dcCred = Get-CredFor -Domain $dom -Default $Credential -Map $DomainCredentials
                $dcParams = @{ Filter = '*'; Server = $dom; ErrorAction = 'Stop' }
                if ($dcCred) { $dcParams['Credential'] = $dcCred }
                $dcs = Get-ADDomainController @dcParams
                foreach ($dc in $dcs) {
                    $dcShort = ($dc.HostName -split '\.')[0]
                    [void]$dcShortNames.Add($dcShort.ToLower())
                    if (-not $machineIndex.ContainsKey($dcShort)) {
                        $machineIndex[$dcShort] = @{ Type='VM'; ParentHost='(domain controller)'; Cluster=''; Domain=$dom }
                    }
                }
            } catch {
                Write-CLog "Cipher Audit: could not enumerate DCs in $dom -- $($_.Exception.Message)" 'Warning'
            }
        }
    }

    # Per-machine AD computer-object lookup for msDS-SupportedEncryptionTypes.
    $etypeProps = 'msDS-SupportedEncryptionTypes','operatingSystem','operatingSystemVersion','dNSHostName','distinguishedName','whenChanged','Enabled'
    foreach ($short in ($machineIndex.Keys | Sort-Object)) {
        $mi   = $machineIndex[$short]
        $isDC = $dcShortNames.Contains($short.ToLower())

        $adObj = $null
        $adErr = ''
        if ($adAvailable) {
            $searchDomains = @()
            if ($mi.Domain) { $searchDomains += $mi.Domain.ToLower() }
            foreach ($d in $domainSet) { if ($d -notin $searchDomains) { $searchDomains += $d } }
            foreach ($dom in $searchDomains) {
                try {
                    $acred = Get-CredFor -Domain $dom -Default $Credential -Map $DomainCredentials
                    $gp = @{ Identity = $short; Properties = $etypeProps; Server = $dom; ErrorAction = 'Stop' }
                    if ($acred) { $gp['Credential'] = $acred }
                    $adObj = Get-ADComputer @gp
                    if ($adObj) { $mi.Domain = $dom; break }
                } catch {
                    $adErr = $_.Exception.Message
                }
            }
        }

        # Local registry Kerberos etype (from Phase 1) as a cross-check.
        $rawKey = if ($mi.Type -eq 'Host') { "Host|$short" } else { "VM|$short" }
        $localKerb = $null
        $localOSCaption = ''
        foreach ($k in $cipherRaw.Keys) {
            if (($k -split '\|')[1] -eq $short) {
                $rr = $cipherRaw[$k].Raw
                if ($rr -and -not $rr.Error) {
                    $localKerb = $rr.LocalKerbEtypes
                    $localOSCaption = $rr.OSCaption
                    if ($rr.IsDC) { $isDC = $true }
                }
                break
            }
        }

        $adValue = $null
        if ($adObj) {
            $adValue = $adObj.'msDS-SupportedEncryptionTypes'
        }
        $decoded = ConvertTo-EtypeDecode -Value $adValue
        $localDecoded = ConvertTo-EtypeDecode -Value $localKerb

        $osCaption = if ($adObj -and $adObj.operatingSystem) { $adObj.operatingSystem } elseif ($localOSCaption) { $localOSCaption } else { '' }

        # Alert level for this machine's etype posture.
        $alert = 'Info'
        $alertReason = ''
        if ($decoded.DES) {
            $alert = 'Critical'; $alertReason = 'DES enabled -- broken cipher, blocks modern Kerberos and trust validation.'
        }
        elseif (-not $decoded.IsConfigured) {
            $alert = 'Info'; $alertReason = 'Not configured -- OS default (RC4 + AES). Acceptable transitional state.'
        }
        elseif ($decoded.AESOnly) {
            $alert = 'Warning'; $alertReason = 'AES-only. Strong, but any RC4-only partner will fail Kerberos against this account. Confirm all partners support AES.'
        }
        elseif ($decoded.RC4 -and -not $decoded.AES128 -and -not $decoded.AES256) {
            $alert = 'Warning'; $alertReason = 'RC4-only. Will fail against any AES-only DC or trust partner once RC4 is disabled there.'
        }

        $etypeRows.Add([PSCustomObject]@{
            MachineName         = $short
            Type                = $mi.Type
            DataSource          = 'Active Directory'
            IsDomainController  = if ($isDC) { 'Yes' } else { 'No' }
            ParentHost          = $mi.ParentHost
            ClusterName         = $mi.Cluster
            Domain              = $mi.Domain
            OSCaption           = $osCaption
            ADObjectFound       = if ($adObj) { 'Yes' } else { 'No' }
            DistinguishedName   = if ($adObj) { $adObj.distinguishedName } else { '' }
            msDS_RawValue       = $decoded.Raw
            EncryptionCategory  = $decoded.Category
            KerberosEtypes      = $decoded.KrbEtypes
            EtypeNumbers        = $decoded.EtypeNumbers
            RC4_Enabled         = if (-not $decoded.IsConfigured) { 'Yes (default)' } elseif ($decoded.RC4) { 'Yes' } else { 'No' }
            AES128_Enabled      = if (-not $decoded.IsConfigured) { 'Yes (default)' } elseif ($decoded.AES128) { 'Yes' } else { 'No' }
            AES256_Enabled      = if (-not $decoded.IsConfigured) { 'Yes (default)' } elseif ($decoded.AES256) { 'Yes' } else { 'No' }
            DES_Enabled         = if ($decoded.DES) { 'Yes' } else { 'No' }
            LocalRegEtypeValue  = $localDecoded.Raw
            LocalRegEtypeDecode = $localDecoded.Category
            ADvsLocalMatch      = if (-not $adObj) { 'N/A (no AD object)' }
                                  elseif (-not $localKerb -and -not $decoded.IsConfigured) { 'Match (both default)' }
                                  elseif ("$adValue" -eq "$localKerb") { 'Match' }
                                  else { 'Differs (AD account vs local LSA policy)' }
            AlertLevel          = $alert
            Recommendation      = $alertReason
            ADError             = $adErr
        })
    }
    Write-CLog "Cipher Audit: Kerberos etype audit complete -- $($etypeRows.Count) machines, $($dcShortNames.Count) DCs"

    # =================================================================
    # PHASE 3 -- OS-version interoperability matrix
    # =================================================================
    # Group machines that have usable cipher data by normalized OS key.
    $osGroups = @{}
    foreach ($k in $cipherRaw.Keys) {
        $rr = $cipherRaw[$k].Raw
        if (-not $rr -or $rr.Error) { continue }
        $isDC = [bool]$rr.IsDC
        $gk = Get-OSGroupKey -Caption $rr.OSCaption -IsDC $isDC
        if (-not $osGroups.ContainsKey($gk)) { $osGroups[$gk] = [System.Collections.Generic.List[object]]::new() }
        $osGroups[$gk].Add($rr)
    }

    $fleetAllCiphers = $null   # running intersection across every machine
    foreach ($gk in ($osGroups.Keys | Sort-Object)) {
        $members = $osGroups[$gk]
        $count   = $members.Count

        # Cipher-suite intersection -- what every machine in the group can negotiate.
        $common = $null
        $union  = New-Object System.Collections.Generic.HashSet[string]
        foreach ($m in $members) {
            $set = New-Object System.Collections.Generic.HashSet[string]
            foreach ($c in $m.RuntimeCiphers) { [void]$set.Add($c); [void]$union.Add($c) }
            if ($null -eq $common) { $common = $set }
            else { $common.IntersectWith($set) }
            if ($null -eq $fleetAllCiphers) { $fleetAllCiphers = (New-Object System.Collections.Generic.HashSet[string] $set) }
            else { $fleetAllCiphers.IntersectWith($set) }
        }
        if ($null -eq $common) { $common = New-Object System.Collections.Generic.HashSet[string] }

        $commonArr   = @($common)    | Sort-Object
        $divergent   = @($union | Where-Object { -not $common.Contains($_) }) | Sort-Object
        $weakCommon  = @($commonArr | Where-Object { Test-WeakCipherName $_ })
        $critCommon  = @($commonArr | Where-Object { Test-CritCipherName $_ })

        # Protocol intersection.
        $protoCommon = [System.Collections.Generic.List[string]]::new()
        foreach ($pName in 'TLS 1.3','TLS 1.2','TLS 1.1','TLS 1.0','SSL 3.0','SSL 2.0') {
            $allEnabled = $true
            foreach ($m in $members) {
                $st = if ($m.Protocols -and $m.Protocols[$pName]) { $m.Protocols[$pName].Server } else { 'System Default' }
                if ($st -eq 'Disabled' -or $st -eq 'DisabledByDefault') { $allEnabled = $false; break }
            }
            if ($allEnabled) { $protoCommon.Add($pName) }
        }

        $risk = 'OK'
        if ($critCommon.Count -gt 0)        { $risk = 'Critical' }
        elseif ($commonArr.Count -eq 0)     { $risk = 'Critical' }
        elseif ($weakCommon.Count -gt 0)    { $risk = 'Warning' }
        elseif ($divergent.Count -gt 0)     { $risk = 'Warning' }

        $note = ''
        if ($commonArr.Count -eq 0) { $note = 'No cipher suite is common to every machine in this group -- interoperability is NOT guaranteed within the group.' }
        elseif ($divergent.Count -gt 0) { $note = "$($divergent.Count) cipher(s) present on some but not all machines -- those will only work between the machines that share them." }
        else { $note = 'All machines in this group expose an identical cipher set.' }

        $interop.Add([PSCustomObject]@{
            OSVersionGroup       = $gk
            MachineCount         = $count
            CommonProtocols      = if ($protoCommon.Count) { ($protoCommon -join ', ') } else { 'NONE common' }
            CommonCipherCount    = $commonArr.Count
            CommonCipherSuites   = if ($commonArr.Count) { ($commonArr -join '; ') } else { 'NONE' }
            DivergentCipherCount = $divergent.Count
            DivergentCiphers     = if ($divergent.Count) { ($divergent -join '; ') } else { '' }
            WeakCommonCiphers    = if ($weakCommon.Count) { ($weakCommon -join '; ') } else { 'None' }
            CriticalCommonCiphers= if ($critCommon.Count) { ($critCommon -join '; ') } else { 'None' }
            InteropRisk          = $risk
            Notes                = $note
        })
    }

    # Fleet-wide lowest common denominator row.
    if ($null -ne $fleetAllCiphers) {
        $lcd = @($fleetAllCiphers) | Sort-Object
        $lcdWeak = @($lcd | Where-Object { Test-WeakCipherName $_ })
        $interop.Add([PSCustomObject]@{
            OSVersionGroup       = 'ALL MACHINES (cross-fleet lowest common denominator)'
            MachineCount         = $cipherRows.Count
            CommonProtocols      = '(see per-OS rows)'
            CommonCipherCount    = $lcd.Count
            CommonCipherSuites   = if ($lcd.Count) { ($lcd -join '; ') } else { 'NONE -- no single cipher works across the entire fleet' }
            DivergentCipherCount = 0
            DivergentCiphers     = ''
            WeakCommonCiphers    = if ($lcdWeak.Count) { ($lcdWeak -join '; ') } else { 'None' }
            CriticalCommonCiphers= ''
            InteropRisk          = if ($lcd.Count -eq 0) { 'Critical' } elseif ($lcdWeak.Count -gt 0) { 'Warning' } else { 'OK' }
            Notes                = 'These cipher suites are negotiable on EVERY machine that returned data. They are the guaranteed-interoperable set for fleet-wide communication. If this list is short or weak, plan a coordinated cipher policy change.'
        })
    }
    Write-CLog "Cipher Audit: interop matrix complete -- $($interop.Count) group rows"

    # =================================================================
    # PHASE 4 -- trust / secure-channel / file-share diagnostics
    # =================================================================
    # Fleet-level etype posture from the etype rows.
    $dcEtypes      = @($etypeRows | Where-Object { $_.IsDomainController -eq 'Yes' })
    $memberEtypes  = @($etypeRows | Where-Object { $_.IsDomainController -ne 'Yes' })
    $rc4OnlyMembers = @($memberEtypes | Where-Object { $_.RC4_Enabled -like 'Yes*' -and $_.AES128_Enabled -eq 'No' -and $_.AES256_Enabled -eq 'No' })
    $aesOnlyDCs     = @($dcEtypes | Where-Object { ($_.AES128_Enabled -eq 'Yes' -or $_.AES256_Enabled -eq 'Yes') -and $_.RC4_Enabled -eq 'No' })
    $desMachines    = @($etypeRows | Where-Object { $_.DES_Enabled -eq 'Yes' })

    # Finding A -- DES anywhere (the classic "trust cannot be updated" cause).
    foreach ($m in $desMachines) {
        $diagRows.Add([PSCustomObject]@{
            AffectedMachine = $m.MachineName
            Type            = $m.Type
            IsDC            = $m.IsDomainController
            Domain          = $m.Domain
            IssueType       = 'DES-Enabled'
            Severity        = 'Critical'
            Evidence        = "msDS-SupportedEncryptionTypes = $($m.msDS_RawValue) ($($m.EncryptionCategory)). DES bits are set."
            RootCause       = 'DES (etype 1/3) is disabled by default on every supported Windows version. An account or trust object still advertising DES cannot complete Kerberos with modern partners; netdom trust /verify and AD trust validation fail.'
            Remediation     = "Clear the DES bits. Set msDS-SupportedEncryptionTypes to 28 (RC4+AES) -- or 24 (AES-only) if the whole domain is AES-ready. Example: Set-ADComputer $($m.MachineName) -Replace @{ 'msDS-SupportedEncryptionTypes' = 28 }"
        })
    }

    # Finding B -- AES-only DC while RC4-only members still exist.
    if ($aesOnlyDCs.Count -gt 0 -and $rc4OnlyMembers.Count -gt 0) {
        foreach ($dc in $aesOnlyDCs) {
            $diagRows.Add([PSCustomObject]@{
                AffectedMachine = $dc.MachineName
                Type            = $dc.Type
                IsDC            = 'Yes'
                Domain          = $dc.Domain
                IssueType       = 'KDC-Etype-Mismatch'
                Severity        = 'Critical'
                Evidence        = "DC etype = $($dc.EncryptionCategory). $($rc4OnlyMembers.Count) member machine(s) are RC4-only (e.g. $(@($rc4OnlyMembers | Select-Object -First 3 | ForEach-Object { $_.MachineName }) -join ', '))."
                RootCause       = 'This domain controller offers only AES. RC4-only member computers and trust accounts cannot obtain Kerberos tickets from it (KDC_ERR_ETYPE_NOTSUPP). Result: Netlogon secure channel breaks, SMB/file-share access to those members fails, and trust verification through this DC fails.'
                Remediation     = "Either (a) move the RC4-only members to value 28 (RC4+AES) first, then leave the DC AES-only, or (b) temporarily set the DC to 28 until every member is AES-capable. Do NOT leave the domain split. Audit 4768/4769 events for etype 23 before going AES-only."
            })
        }
    }

    # Finding C -- RC4-only members at risk (latent, if any DC has AES-capable posture).
    if ($rc4OnlyMembers.Count -gt 0) {
        foreach ($m in $rc4OnlyMembers) {
            $diagRows.Add([PSCustomObject]@{
                AffectedMachine = $m.MachineName
                Type            = $m.Type
                IsDC            = 'No'
                Domain          = $m.Domain
                IssueType       = 'SecureChannel-Risk'
                Severity        = 'Warning'
                Evidence        = "msDS-SupportedEncryptionTypes = $($m.msDS_RawValue) (RC4-only)."
                RootCause       = 'This member advertises RC4 only. The moment RC4 is disabled on the DCs (or domain-wide Kerberos hardening is applied) this machine loses its secure channel and SMB access to AES-only servers.'
                Remediation     = "Set msDS-SupportedEncryptionTypes to 28 (RC4 + AES128 + AES256) now so it negotiates AES where possible and is ready for the eventual RC4 removal. Example: Set-ADComputer $($m.MachineName) -Replace @{ 'msDS-SupportedEncryptionTypes' = 28 }"
            })
        }
    }

    # Finding D -- DC etype intersection check (the domain-wide negotiation floor).
    if ($dcEtypes.Count -gt 1) {
        $dcRC4 = @($dcEtypes | Where-Object { $_.RC4_Enabled -like 'Yes*' }).Count
        $dcAES = @($dcEtypes | Where-Object { $_.AES128_Enabled -like 'Yes*' -or $_.AES256_Enabled -like 'Yes*' }).Count
        $inconsistent = ($dcRC4 -ne 0 -and $dcRC4 -ne $dcEtypes.Count) -or ($dcAES -ne 0 -and $dcAES -ne $dcEtypes.Count)
        if ($inconsistent) {
            $diagRows.Add([PSCustomObject]@{
                AffectedMachine = '(all domain controllers)'
                Type            = 'VM'
                IsDC            = 'Yes'
                Domain          = '(forest)'
                IssueType       = 'DC-Etype-Inconsistency'
                Severity        = 'Critical'
                Evidence        = "$($dcEtypes.Count) DCs audited. RC4-capable: $dcRC4. AES-capable: $dcAES. The DC set is not uniform."
                RootCause       = 'Domain controllers do not all advertise the same Kerberos encryption types. Authentication behaviour then depends on which DC a client happens to contact, producing intermittent secure-channel, trust and file-share failures that are very hard to diagnose.'
                Remediation     = 'Make every DC identical. During migration set ALL DCs to 28 (RC4+AES). Only move ALL DCs to 24 (AES-only) together, after confirming no RC4 tickets remain.'
            })
        }
    }

    # Finding E -- machines with no AD object (cannot have an etype managed).
    foreach ($m in @($etypeRows | Where-Object { $_.ADObjectFound -eq 'No' })) {
        $diagRows.Add([PSCustomObject]@{
            AffectedMachine = $m.MachineName
            Type            = $m.Type
            IsDC            = $m.IsDomainController
            Domain          = $m.Domain
            IssueType       = 'No-AD-Object'
            Severity        = 'Warning'
            Evidence        = if ($m.ADError) { "Get-ADComputer failed: $($m.ADError)" } else { 'No matching computer object found in the searched domain(s).' }
            RootCause       = 'No Active Directory computer object was located for this machine, so its Kerberos encryption-type posture cannot be confirmed. The machine may be workgroup-joined, in an untrusted domain, or named differently in AD than in Hyper-V.'
            Remediation     = 'Confirm the machine is domain-joined and that the guest hostname matches its AD computer object name (see the NameMatch column on vInfo). Re-run once corrected.'
        })
    }

    if ($diagRows.Count -eq 0) {
        $diagRows.Add([PSCustomObject]@{
            AffectedMachine = '(none)'
            Type            = ''
            IsDC            = ''
            Domain          = ''
            IssueType       = 'No-Issues-Detected'
            Severity        = 'Info'
            Evidence        = "All $($etypeRows.Count) audited machines have a consistent, AES-capable Kerberos etype posture with no DES."
            RootCause       = 'No msDS-SupportedEncryptionTypes mismatch was found that would explain trust, secure-channel or file-share failures.'
            Remediation     = 'If failures are still occurring, look elsewhere: time skew (>5 min breaks Kerberos), SPN duplicates/missing SPNs, DNS, or the SCHANNEL/TLS layer on the Cipher-Audit tab.'
        })
    }
    Write-CLog "Cipher Audit: diagnostics complete -- $($diagRows.Count) finding rows"

    return @{
        CipherAudit       = $cipherRows
        KerberosEtypes    = $etypeRows
        CipherInterop     = $interop
        CipherDiagnostics = $diagRows
        EtypeReference    = (Get-CipherEtypeReferenceData)
    }
}


# Build one Cipher-Audit row from a raw collection result.
function New-CipherRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Raw,
        [Parameter(Mandatory = $true)][string]$MachineName,
        [Parameter(Mandatory = $true)][string]$MachineType,
        [Parameter(Mandatory = $false)][string]$ParentHost = '',
        [Parameter(Mandatory = $false)][string]$Cluster = ''
    )

    function Test-Weak { param([string]$N) return ($N -match 'RC4|3DES|DES|NULL|MD5|EXPORT|_CBC_') }
    function Test-Crit { param([string]$N) return ($N -match 'NULL|_RC4_|^RC4|EXPORT|_DES_') }

    if ($Raw.Error) {
        return [PSCustomObject]@{
            MachineName       = $MachineName
            Type              = $MachineType
            DataSource        = 'Hyper-V'
            ParentHost        = $ParentHost
            ClusterName       = $Cluster
            IsDomainController= 'Unknown'
            OSCaption         = ''
            OSBuild           = ''
            CollectionMethod  = if ($Raw.CollectionMethod) { $Raw.CollectionMethod } else { 'Failed' }
            SSL2_0            = 'ERROR'
            SSL3_0            = 'ERROR'
            TLS1_0            = 'ERROR'
            TLS1_1            = 'ERROR'
            TLS1_2            = 'ERROR'
            TLS1_3            = 'ERROR'
            CipherSource      = 'ERROR'
            CipherSuiteCount  = 0
            WeakCipherCount   = 0
            CriticalCipherCount = 0
            WeakCiphers       = ''
            CriticalCiphers   = ''
            NegotiableCiphers = ''
            LocalKerberosEtype= ''
            Status            = 'ERROR'
            ErrorDetail       = $Raw.Error
        }
    }

    function Get-PStatus { param($P,$Name)
        if ($P -and $P[$Name]) {
            $sv = $P[$Name].Server; $cl = $P[$Name].Client
            if ($sv -eq $cl) { return $sv } else { return "S:$sv / C:$cl" }
        }
        return 'Not Set'
    }

    $ciphers = @($Raw.RuntimeCiphers)
    $weak = @($ciphers | Where-Object { Test-Weak $_ })
    $crit = @($ciphers | Where-Object { Test-Crit $_ })

    $status = 'OK'
    if ($crit.Count -gt 0) { $status = 'CRITICAL' }
    elseif ($weak.Count -gt 0) { $status = 'WEAK' }

    $localKerb = ConvertTo-EtypeDecode -Value $Raw.LocalKerbEtypes

    return [PSCustomObject]@{
        MachineName        = $MachineName
        Type               = $MachineType
        DataSource         = 'Hyper-V'
        ParentHost         = $ParentHost
        ClusterName        = $Cluster
        IsDomainController = if ($Raw.IsDC) { 'Yes' } else { 'No' }
        OSCaption          = $Raw.OSCaption
        OSBuild            = $Raw.OSBuild
        CollectionMethod   = if ($Raw.CollectionMethod) { $Raw.CollectionMethod } else { 'WinRM' }
        SSL2_0             = Get-PStatus $Raw.Protocols 'SSL 2.0'
        SSL3_0             = Get-PStatus $Raw.Protocols 'SSL 3.0'
        TLS1_0             = Get-PStatus $Raw.Protocols 'TLS 1.0'
        TLS1_1             = Get-PStatus $Raw.Protocols 'TLS 1.1'
        TLS1_2             = Get-PStatus $Raw.Protocols 'TLS 1.2'
        TLS1_3             = Get-PStatus $Raw.Protocols 'TLS 1.3'
        CipherSource       = $Raw.CipherSource
        CipherSuiteCount   = $ciphers.Count
        WeakCipherCount    = $weak.Count
        CriticalCipherCount= $crit.Count
        WeakCiphers        = if ($weak.Count) { ($weak -join '; ') } else { 'None' }
        CriticalCiphers    = if ($crit.Count) { ($crit -join '; ') } else { 'None' }
        NegotiableCiphers  = if ($ciphers.Count) { ($ciphers -join '; ') } else { '' }
        LocalKerberosEtype = "$($localKerb.Raw) ($($localKerb.Category))"
        Status             = $status
        ErrorDetail        = if ($Raw.Errors -and $Raw.Errors.Count) { ($Raw.Errors -join '; ') } else { '' }
    }
}


# =====================================================================
# EXPORT -- writes the five worksheets into the workbook
# =====================================================================

function Export-CipherAuditTabs {
    <#
    .SYNOPSIS
        Writes the Cipher-Audit, Kerberos-Etypes, Cipher-Interop,
        Cipher-Diagnostics and Etype-Reference worksheets.

    .PARAMETER ExcelParams
        The base $params splat used by Export-HyperVInventoryToExcel
        (Path / AutoSize / FreezeTopRow / TableStyle).

    .PARAMETER CipherAuditData
        The hashtable returned by Invoke-CipherEncryptionAudit.

    .PARAMETER ReportLevel
        Basic / Intermediate / Advanced. All five tabs are written at every
        level (security content is wanted on every report level).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$ExcelParams,
        [Parameter(Mandatory = $true)][hashtable]$CipherAuditData,
        [Parameter(Mandatory = $false)][string]$ReportLevel = 'Advanced'
    )

    if (-not (Get-Command -Name 'Export-Excel' -ErrorAction SilentlyContinue)) {
        Write-Verbose 'Export-CipherAuditTabs: ImportExcel not available -- skipping'
        return
    }
    $hasLog = [bool](Get-Command -Name 'Write-HVLog' -ErrorAction SilentlyContinue)
    function Log { param($m,$l='Info') if ($hasLog) { Write-HVLog "  $m" -Level $l } else { Write-Verbose $m } }

    $p = $ExcelParams.Clone()

    # ---- Cipher-Audit ----
    if ($CipherAuditData.CipherAudit -and @($CipherAuditData.CipherAudit).Count -gt 0) {
        $rows = @($CipherAuditData.CipherAudit)
        $p.TableStyle = 'Medium6'
        $rows | Sort-Object Status, Type, MachineName |
            Export-Excel @p -WorksheetName 'Cipher-Audit' `
                -Title 'Cipher / SCHANNEL Audit -- Per-Machine Runtime State (every host and VM)' `
                -ConditionalText @(
                    New-ConditionalText -Text 'CRITICAL'          -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                    New-ConditionalText -Text 'WEAK'               -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                    New-ConditionalText -Text 'OK'                 -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                    New-ConditionalText -Text 'ERROR'              -BackgroundColor '#E0E0E0' -ConditionalTextColor '#666666'
                    New-ConditionalText -Text 'DisabledByDefault'  -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                    New-ConditionalText -Text 'Disabled'           -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                )
        $crit = @($rows | Where-Object { $_.Status -eq 'CRITICAL' }).Count
        $weak = @($rows | Where-Object { $_.Status -eq 'WEAK' }).Count
        Log "Cipher-Audit: $($rows.Count) machines -- $crit critical, $weak weak"
        $p.TableStyle = 'Medium2'
    }

    # ---- Kerberos-Etypes ----
    if ($CipherAuditData.KerberosEtypes -and @($CipherAuditData.KerberosEtypes).Count -gt 0) {
        $rows = @($CipherAuditData.KerberosEtypes)
        $p.TableStyle = 'Medium6'
        $rows | Sort-Object AlertLevel, IsDomainController, MachineName |
            Export-Excel @p -WorksheetName 'Kerberos-Etypes' `
                -Title 'Kerberos Encryption Types -- msDS-SupportedEncryptionTypes Decoded (per machine)' `
                -ConditionalText @(
                    New-ConditionalText -Text 'Critical' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                    New-ConditionalText -Text 'Warning'  -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                    New-ConditionalText -Text 'Info'     -BackgroundColor '#E3F2FD' -ConditionalTextColor '#1565C0'
                    New-ConditionalText -Text 'Differs'  -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                )
        $kc = @($rows | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
        $kw = @($rows | Where-Object { $_.AlertLevel -eq 'Warning' }).Count
        Log "Kerberos-Etypes: $($rows.Count) machines -- $kc critical, $kw warning"
        $p.TableStyle = 'Medium2'
    }

    # ---- Cipher-Interop ----
    if ($CipherAuditData.CipherInterop -and @($CipherAuditData.CipherInterop).Count -gt 0) {
        $rows = @($CipherAuditData.CipherInterop)
        $p.TableStyle = 'Medium9'
        $rows |
            Export-Excel @p -WorksheetName 'Cipher-Interop' `
                -Title 'Cipher Interoperability -- Common Negotiable Ciphers by OS Version (DCs broken out)' `
                -ConditionalText @(
                    New-ConditionalText -Text 'Critical' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                    New-ConditionalText -Text 'Warning'  -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                    New-ConditionalText -Text 'OK'       -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                )
        Log "Cipher-Interop: $($rows.Count) OS-version group rows"
        $p.TableStyle = 'Medium2'
    }

    # ---- Cipher-Diagnostics ----
    if ($CipherAuditData.CipherDiagnostics -and @($CipherAuditData.CipherDiagnostics).Count -gt 0) {
        $rows = @($CipherAuditData.CipherDiagnostics)
        $p.TableStyle = 'Medium6'
        $rows | Sort-Object Severity, IssueType, AffectedMachine |
            Export-Excel @p -WorksheetName 'Cipher-Diagnostics' `
                -Title 'Cipher Diagnostics -- Trust / Secure Channel / File Share Failure Analysis' `
                -ConditionalText @(
                    New-ConditionalText -Text 'Critical' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                    New-ConditionalText -Text 'Warning'  -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                    New-ConditionalText -Text 'Info'     -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                )
        $dc = @($rows | Where-Object { $_.Severity -eq 'Critical' }).Count
        Log "Cipher-Diagnostics: $($rows.Count) findings -- $dc critical"
        $p.TableStyle = 'Medium2'
    }

    # ---- Etype-Reference ----
    if ($CipherAuditData.EtypeReference -and @($CipherAuditData.EtypeReference).Count -gt 0) {
        $rows = @($CipherAuditData.EtypeReference)
        $p.TableStyle = 'Medium15'
        $rows |
            Export-Excel @p -WorksheetName 'Etype-Reference' `
                -Title 'Encryption Type Reference -- Value Table, Bit Meanings, and Failure Explanations'
        Log "Etype-Reference: $($rows.Count) reference rows"
        $p.TableStyle = 'Medium2'
    }
}


Export-ModuleMember -Function @(
    'Invoke-CipherEncryptionAudit'
    'Export-CipherAuditTabs'
    'Get-CipherEtypeReferenceData'
    'ConvertTo-EtypeDecode'
    'New-CipherRow'
)
