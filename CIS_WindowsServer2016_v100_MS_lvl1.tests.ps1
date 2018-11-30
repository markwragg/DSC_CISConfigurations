#Install pre-req modules
Try {
    If (-not (Get-Module -Name PoshSpec -ListAvailable)) {
        Install-Module -Name PoshSpec
    }
}
Catch {
    Write-Error $_
    Throw 'Failed to install PoshSpec, cannot continue.'
}

Import-Module -Name PoshSpec

function Get-SecurityPolicy {
    $SecurityPolicyFilePath = Join-Path -Path $env:temp -ChildPath 'SecurityPolicy.inf'
    secedit.exe /export /cfg $SecurityPolicyFilePath /areas 'SECURITYPOLICY' | Out-Null

    $policyConfiguration = @{}
    switch -regex -file $SecurityPolicyFilePath
    {
        "^\[(.+)\]" # Section
        {
            $section = $matches[1]
            $policyConfiguration[$section] = @{}
            $CommentCount = 0
        }
        "^(;.*)$" # Comment
        {
            $value = $matches[1]
            $commentCount = $commentCount + 1
            $name = "Comment" + $commentCount
            $policyConfiguration[$section][$name] = $value
        }
        "(.+?)\s*=(.*)" # Key
        {
            $name,$value =  $matches[1..2] -replace "\*"
            $policyConfiguration[$section][$name] = $value
        }
    }

    Return $policyConfiguration
}

#Pester Tests for CIS Level 1 hardening standards for Member Servers
Describe 'CIS Windows Server 2016 v1.0.0 Member Server Level 1' {

    Context 'User Rights Assignment' {
        #Note: UserRights tests must be run with Administrator rights and use the PoshSpec module.

        # 2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One' 
        UserRightsAssignment ByRight 'SeTrustedCredManAccessPrivilege' { 
            Should -Be $null -Because '2.2.1 (L1)'
        }

        # 2.2.2 (L1) Configure 'Access this computer from the network'
        UserRightsAssignment ByRight 'SeNetworkLogonRight' { 
            Should -Contain 'BUILTIN\Administrators' -Because '2.2.2 (L1)'
        }

        # 2.2.2 (L1) Configure 'Access this computer from the network'
        UserRightsAssignment ByRight 'SeNetworkLogonRight' { 
            Should -Contain 'NT AUTHORITY\Authenticated Users' -Because '2.2.2 (L1)'
        }

        # 2.2.2 (L1) Configure 'Access this computer from the network'
        UserRightsAssignment ByRight 'SeNetworkLogonRight' { 
            Should -HaveCount 2 -Because '2.2.2 (L1)'
        }
    
        # 2.2.3 (L1) Ensure 'Act as part of the operating system' is set to 'No One'
        UserRightsAssignment ByRight 'SeTcbPrivilege' { 
            Should -Be $null -Because '2.2.3 (L1)'
        }

        # 2.2.5 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE' 
        UserRightsAssignment ByRight 'SeIncreaseQuotaPrivilege' { 
            Should -Contain 'BUILTIN\Administrators' -Because '2.2.5 (L1)'
        }

        # 2.2.5 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE' 
        UserRightsAssignment ByRight 'SeIncreaseQuotaPrivilege' { 
            Should -Contain 'NT AUTHORITY\NETWORK SERVICE' -Because '2.2.5 (L1)'
        }

        # 2.2.5 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE' 
        UserRightsAssignment ByRight 'SeIncreaseQuotaPrivilege' { 
            Should -Contain 'NT AUTHORITY\LOCAL SERVICE' -Because '2.2.5 (L1)'
        }

        # 2.2.5 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE' 
        UserRightsAssignment ByRight 'SeIncreaseQuotaPrivilege' { 
            Should -HaveCount 3 -Because '2.2.5 (L1)'
        }
    
        # 2.2.6 (L1) Configure 'Allow log on locally'
        UserRightsAssignment ByRight 'SeInteractiveLogonRight' { 
            Should -Be 'BUILTIN\Administrators' -Because '2.2.6 (L1)'
        }

        # 2.2.7 (L1) Configure 'Allow log on through Remote Desktop Services'
        UserRightsAssignment ByRight 'SeRemoteInteractiveLogonRight' { 
            Should -Be 'BUILTIN\Administrators' -Because '2.2.7 (L1)'
        }

        # 2.2.8 (L1) Ensure 'Back up files and directories' is set to 'BUILTIN\Administrators'
        UserRightsAssignment ByRight 'SeBackupPrivilege' {
            Should -Be 'BUILTIN\Administrators' -Because '2.2.8 (L1)'
        }

        # 2.2.9 (L1) Ensure 'Change the system time' is set to 'BUILTIN\Administrators','NT AUTHORITY\LOCAL SERVICE' 
        UserRightsAssignment ByRight 'SeSystemtimePrivilege' {
            Should -Be 'BUILTIN\Administrators', 'NT AUTHORITY\LOCAL SERVICE' -Because '2.2.9 (L1)'
        }

        # 2.2.10 (L1) Ensure 'Change the time zone' is set to 'BUILTIN\Administrators','NT AUTHORITY\LOCAL SERVICE'
        UserRightsAssignment ByRight 'SeTimeZonePrivilege' {
            Should -Be 'BUILTIN\Administrators', 'NT AUTHORITY\LOCAL SERVICE' -Because '2.2.10 (L1)'
        }

        # 2.2.11 (L1) Ensure 'Create a pagefile' is set to 'BUILTIN\Administrators'
        UserRightsAssignment ByRight 'SeCreatePagefilePrivilege' {
            Should -Be 'BUILTIN\Administrators' -Because '2.2.11 (L1)'
        }

        # 2.2.12 (L1) Ensure 'Create a token object' is set to 'No One'
        UserRightsAssignment ByRight 'SeCreateTokenPrivilege' {
            Should -Be $null -Because '2.2.12 (L1)'
        }
    
        # 2.2.13 (L1) Ensure 'Create global objects' is set to 'BUILTIN\Administrators,NT AUTHORITY\LOCAL SERVICE, NT AUTHORITY\NETWORK SERVICE, NT AUTHORITY\SERVICE'
        UserRightsAssignment ByRight 'SeCreateGlobalPrivilege' {
            Should -Be 'NT AUTHORITY\SERVICE', 'BUILTIN\Administrators', 'NT AUTHORITY\NETWORK SERVICE', 'NT AUTHORITY\LOCAL SERVICE' -Because '2.2.13 (L1)'
        }

        # 2.2.14 (L1) Ensure 'Create permanent shared objects' is set to 'No One'
        UserRightsAssignment ByRight 'SeCreatePermanentPrivilege' {
            Should -Be $null -Because '2.2.14 (L1)'
        }

        # 2.2.15 (L1) Configure 'Create symbolic links'
        UserRightsAssignment ByRight 'SeCreateSymbolicLinkPrivilege' {
            Should -Be 'BUILTIN\Administrators' -Because '2.2.15 (L1)'
        }

        # 2.2.16 (L1) Ensure 'Debug programs' is set to 'BUILTIN\Administrators'
        UserRightsAssignment ByRight 'SeDebugPrivilege' {
            Should -Be 'BUILTIN\Administrators' -Because '2.2.16 (L1)'
        }

        # 2.2.17 (L1) Configure 'Deny access to this computer from the network' - Excluded for Workgroup Server
        UserRightsAssignment ByRight 'SeDenyNetworkLogonRight' {
            Should -Be $null -Because '2.2.17 (L1)'
        }

        # 2.2.18 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'
        UserRightsAssignment ByRight 'SeDenyBatchLogonRight' {
            Should -Be 'BUILTIN\Guests' -Because '2.2.18 (L1)'
        }

        # 2.2.19 (L1) Ensure 'Deny log on as a service' to include 'Guests'
        UserRightsAssignment ByRight 'SeDenyServiceLogonRight' {
            Should -Be 'BUILTIN\Guests' -Because '2.2.19 (L1)'
        }

        # 2.2.20 (L1) Ensure 'Deny log on locally' to include 'Guests'
        UserRightsAssignment ByRight 'SeDenyInteractiveLogonRight' {
            Should -Be 'BUILTIN\Guests' -Because '2.2.20 (L1)'
        }

        # 2.2.21 (L1) Ensure 'Deny log on through Remote Desktop Services' to include 'Guests, Local account' - Excluded for Workgroup Server
        UserRightsAssignment ByRight 'SeDenyRemoteInteractiveLogonRight' {
            Should -Be $null -Because '2.2.21 (L1)'
        }

        # 2.2.22 (L1) Configure 'Enable computer and user accounts to be trusted for delegation'
        UserRightsAssignment ByRight 'SeEnableDelegationPrivilege' {
            Should -Be $null -Because '2.2.22 (L1)'
        }

        # 2.2.23 (L1) Ensure 'Force shutdown from a remote system' is set to 'BUILTIN\Administrators'
        UserRightsAssignment ByRight 'SeRemoteShutdownPrivilege' {
            Should -Be 'BUILTIN\Administrators' -Because '2.2.23 (L1)'
        }

        # 2.2.24 (L1) Ensure 'Generate security audits' is set to 'NT AUTHORITY\LOCAL SERVICE,NT AUTHORITY\NETWORK SERVICE'
        UserRightsAssignment ByRight 'SeAuditPrivilege' {
            Should -Be 'NT AUTHORITY\NETWORK SERVICE', 'NT AUTHORITY\LOCAL SERVICE' -Because '2.2.24 (L1)'
        }

        # 2.2.25 (L1) Configure 'Impersonate a client after authentication'
        UserRightsAssignment ByRight 'SeImpersonatePrivilege' {
            Should -Be 'NT AUTHORITY\SERVICE', 'BUILTIN\Administrators', 'NT AUTHORITY\NETWORK SERVICE', 'NT AUTHORITY\LOCAL SERVICE' -Because '2.2.25 (L1)'
        }

        # 2.2.26 (L1) Ensure 'Increase scheduling priority' is set to 'BUILTIN\Administrators'
        UserRightsAssignment ByRight 'SeIncreaseBasePriorityPrivilege' {
            Should -Be 'BUILTIN\Administrators' -Because '2.2.26 (L1)'
        }
 
        # 2.2.27 (L1) Ensure 'Load and unload device drivers' is set to 'BUILTIN\Administrators'
        UserRightsAssignment ByRight 'SeLoadDriverPrivilege' {
            Should -Be 'BUILTIN\Administrators' -Because '2.2.27 (L1)'
        }

        # 2.2.28 (L1) Ensure 'Lock pages in memory' is set to 'No One'
        UserRightsAssignment ByRight 'SeLockMemoryPrivilege' {
            Should -Be $null -Because '2.2.28 (L1)'
        }

        # 2.2.30 (L1) Configure 'Manage auditing and security log'
        UserRightsAssignment ByRight 'SeSecurityPrivilege' {
            Should -Be 'BUILTIN\Administrators' -Because '2.2.30 (L1)'
        }

        # 2.2.31 (L1) Ensure 'Modify an object label' is set to 'No One'
        UserRightsAssignment ByRight 'SeRelabelPrivilege' {
            Should -Be $null -Because '2.2.31 (L1)'
        }

        # 2.2.32 (L1) Ensure 'Modify firmware environment values' is set to 'BUILTIN\Administrators'
        UserRightsAssignment ByRight 'SeSystemEnvironmentPrivilege' {
            Should -Be 'BUILTIN\Administrators' -Because '2.2.32 (L1)'
        }

        # 2.2.33 (L1) Ensure 'Perform volume maintenance tasks' is set to 'BUILTIN\Administrators'
        UserRightsAssignment ByRight 'SeManageVolumePrivilege' {
            Should -Be 'BUILTIN\Administrators' -Because '2.2.33 (L1)'
        }

        # 2.2.34 (L1) Ensure 'Profile single process' is set to 'BUILTIN\Administrators'
        UserRightsAssignment ByRight 'SeProfileSingleProcessPrivilege' {
            Should -Be 'BUILTIN\Administrators' -Because '2.2.34 (L1)'
        }

        # 2.2.35 (L1) Ensure 'Profile system performance' is set to 'BUILTIN\Administrators,NT SERVICE\WdiServiceHost' 
        UserRightsAssignment ByRight 'SeSystemProfilePrivilege' {
            Should -Be 'NT SERVICE\WdiServiceHost', 'BUILTIN\Administrators' -Because '2.2.35 (L1)'
        }

        # 2.2.36 (L1) Ensure 'Replace a process level token' is set to 'LOCALSERVICE, NT AUTHORITY\NETWORK SERVICE'
        UserRightsAssignment ByRight 'SeAssignPrimaryTokenPrivilege' {
            Should -Be 'NT AUTHORITY\NETWORK SERVICE', 'NT AUTHORITY\LOCAL SERVICE' -Because '2.2.36 (L1)'
        }

        # 2.2.37 (L1) Ensure 'Restore files and directories' is set to 'BUILTIN\Administrators'
        UserRightsAssignment ByRight 'SeRestorePrivilege' {
            Should -Be 'BUILTIN\Administrators' -Because '2.2.37 (L1)'
        }

        # 2.2.38 (L1) Ensure 'Shut down the system' is set to 'BUILTIN\Administrators'
        UserRightsAssignment ByRight 'SeShutdownPrivilege' {
            Should -Be 'BUILTIN\Administrators' -Because '2.2.38 (L1)'
        }

        # 2.2.40 (L1) Ensure 'Take ownership of files or other objects' is set to 'BUILTIN\Administrators' 
        UserRightsAssignment ByRight 'SeTakeOwnershipPrivilege' {
            Should -Be 'BUILTIN\Administrators' -Because '2.2.40 (L1)'
        }
    }

    Context 'Security Options' {
        
        $SecurityOptions = Get-SecurityPolicy

        # 2.3.1.1 (L1) Ensure 'Accounts: Administrator account status' is set to 'Disabled' - Override!
        It 'Admin Account should be Enabled' {
            $SecurityOptions.'System Access'.'EnableAdminAccount' | Should -Be 1 -Because '2.3.1.1 (L1)'
        }
        
        # 2.3.1.2 (L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
        Registry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\' 'NoConnectedUser' {
            Should -Be 0 -Because '2.3.1.2 (L1)'
        }

        # 2.3.1.3 (L1) Ensure 'Accounts: Guest account status' is set to 'Disabled'
        It 'Guest Account should be Disabled' {
            $SecurityOptions.'System Access'.'EnableGuestAccount' | Should -Be 0 -Because '2.3.1.3 (L1)'
        }
        
        # 2.3.1.4 (L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
        Registry 'HKLM:\System\CurrentControlSet\Control\Lsa\' 'LimitBlankPasswordUse' {
            Should -Be 1 -Because '2.3.1.4 (L1)'
        }

        # 2.3.2.1 (L1) Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
        Registry 'HKLM:\System\CurrentControlSet\Control\Lsa\' 'SCENoApplyLegacyAuditPolicy' {
            Should -Be 1 -Because '2.3.2.1 (L1)'
        }

        # 2.3.2.2 (L1) Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
        Registry 'HKLM:\System\CurrentControlSet\Control\Lsa\' 'CrashOnAuditFail' {
            Should -Be 0 -Because '2.3.2.2 (L1)'
        }

        # 2.3.4.1 (L1) Ensure 'Devices: Allowed to format and eject removable media' is set to 'BUILTIN\Administrators'
        Registry 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\' 'AllocateDASD' {
            Should -Be "0" -Because '2.3.4.1 (L1)'
        }

        # 2.3.4.2 (L1) Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
        Registry 'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\' 'AddPrinterDrivers' {
            Should -Be 1 -Because '2.3.4.2 (L1)'
        }

        # 2.3.6.1 (L1) Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
        Registry 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\' 'RequireSignOrSeal' {
            Should -Be 1 -Because '2.3.6.1 (L1)'
        }

        # 2.3.6.2 (L1) Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
        Registry 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\' 'SealSecureChannel' {
            Should -Be 1 -Because '2.3.6.2 (L1)'
        }

        # 2.3.6.3 (L1) Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
        Registry 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\' 'SignSecureChannel' {
            Should -Be 1 -Because '2.3.6.3 (L1)'
        }

        # 2.3.6.4 (L1) Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
        Registry 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\' 'DisablePasswordChange' {
            Should -Be 0 -Because '2.3.6.4 (L1)'
        }

        # 2.3.6.5 (L1) Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'
        Registry 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\' 'MaximumPasswordAge' {
            Should -BeLessOrEqual 30 -Because '2.3.6.5 (L1)'
        }

        # 2.3.6.6 (L1) Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled
        Registry 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\' 'RequireStrongKey' {
            Should -Be 1 -Because '2.3.6.6 (L1)'
        }

        # 2.3.7.1 (L1) Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
        Registry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\' 'DontDisplayLastUserName' {
            Should -Be 1 -Because '2.3.7.1 (L1)'
        }

        # 2.3.7.2 (L1) Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
        Registry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\' 'DisableCAD' {
            Should -Be 0 -Because '2.3.7.2 (L1)'
        }
        
        # 2.3.7.3 (L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'
        Registry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\' 'InactivityTimeoutSecs' {
            Should -BeLessOrEqual 900 -Because '2.3.7.3 (L1)'
        }
        
        # 2.3.7.4 (L1) Configure 'Interactive logon: Message text for users attempting to log on'
        Registry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\' 'LegalNoticeText' {
            Should -Be '<Replace with organizational requirements>' -Because '2.3.7.4 (L1)'
        }

         # 2.3.7.5 (L1) Configure 'Interactive logon: Message title for users attempting to log on'
        Registry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\' 'LegalNoticeCaption' {
            Should -Be '<Replace with organizational requirements>' -Because '2.3.7.5 (L1)'
        }

        # 2.3.7.7 (L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'
        Registry 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\' 'PasswordExpiryWarning' {
            Should -BeLessOrEqual 14 -Because '2.3.7.7 (L1)'
        }

        # 2.3.7.7 (L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'
        Registry 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\' 'PasswordExpiryWarning' {
            Should -BeGreaterOrEqual 5 -Because '2.3.7.7 (L1)'
        }

        # 2.3.7.8 (L1) Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled' (MS only)
        Registry 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\' 'ForceUnlockLogon' {
            Should -Be 1 -Because '2.3.7.8 (L1)'
        }

        # 2.3.7.9 (L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher
        Registry 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\' 'ScRemoveOption' {
            Should -Be 1 -Because '2.3.7.9 (L1)'
        }

        # 2.3.8.1 (L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
        Registry 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\' 'RequireSecuritySignature' {
            Should -Be 1 -Because '2.3.8.1 (L1)'
        }

        # 2.3.8.2 (L1) Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
        Registry 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\' 'EnableSecuritySignature' {
            Should -Be 1 -Because '2.3.8.2 (L1)'
        }

        # 2.3.8.3 (L1) Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'
        Registry 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\' 'EnablePlainTextPassword' {
            Should -Be 0 -Because '2.3.8.3 (L1)'
        }

        # 2.3.9.1 (L1) Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'
        Registry 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\' 'AutoDisconnect' {
            Should -BeLessOrEqual 15 -Because '2.3.9.1 (L1)'
        }

        # 2.3.9.1 (L1) Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'
        Registry 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\' 'AutoDisconnect' {
            Should -BeGreaterThan 0 -Because '2.3.9.1 (L1)'
        }

        # 2.3.9.2 (L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
        Registry 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\' 'RequireSecuritySignature' {
            Should -Be 1 -Because '2.3.9.2 (L1)'
        }

        # 2.3.9.3 (L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
        Registry 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\' 'EnableSecuritySignature' {
            Should -Be 1 -Because '2.3.9.3 (L1)'
        }

        # 2.3.9.4 (L1) Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
        Registry 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\' 'EnableForcedLogOff' {
            Should -Be 1 -Because '2.3.9.4 (L1)'
        }

        # 2.3.9.5 (L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher (MS only)
        Registry 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\' 'SmbServerNameHardeningLevel' {
            Should -BeIn 1,2 -Because '2.3.9.5 (L1)'
        }

        # 2.3.10.1 (L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'
        It 'Guest Account should be Disabled' {
            $SecurityOptions.'System Access'.'LSAAnonymousNameLookup' | Should -Be 0 -Because '2.3.10.1 (L1)'
        }

        # 2.3.10.2 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled' (MS only)
        Registry 'HKLM:\System\CurrentControlSet\Control\Lsa\' 'RestrictAnonymousSAM' {
            Should -Be 1 -Because '2.3.10.2 (L1)'
        }

        # 2.3.10.3 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (MS only)
        Registry 'HKLM:\System\CurrentControlSet\Control\Lsa\' 'RestrictAnonymous' {
            Should -Be 1 -Because '2.3.10.3 (L1)'
        }

        # 2.3.10.5 (L1) Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
        Registry 'HKLM:\System\CurrentControlSet\Control\Lsa\' 'EveryoneIncludesAnonymous' {
            Should -Be 0 -Because '2.3.10.5 (L1)'
        }

        # 2.3.10.6 (L1) Configure 'Network access: Named Pipes that can be accessed anonymously'
        Registry 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\' 'NullSessionPipes' {
            Should -Be $null -Because '2.3.10.6 (L1)'
        }

        # 2.3.10.7 (L1) Configure 'Network access: Remotely accessible registry paths'
        
        # 2.3.10.8 (L1) Configure 'Network access: Remotely accessible registry paths and sub-paths'
        
        # 2.3.10.9 (L1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
        Registry 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\' 'RestrictNullSessAccess' {
            Should -Be 1 -Because '2.3.10.9 (L1)'
        }

        # 2.3.10.10 (L1) Ensure 'Network access: Restrict clients allowed to makeremote calls to SAM' is set to 'Administrators: Remote Access: Allow' (MS only)
        
        # 2.3.10.11 (L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'
        Registry 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\' 'NullSessionShares' {
            Should -Be $null -Because '2.3.10.11 (L1)'
        }

        # 2.3.10.12 (L1) Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'
        Registry 'HKLM:\System\CurrentControlSet\Control\Lsa\' 'ForceGuest' {
            Should -Be 0 -Because '2.3.10.12 (L1)'
        }

        # 2.3.11.1 (L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'
        Registry 'HKLM:\System\CurrentControlSet\Control\Lsa\' 'UseMachineId' {
            Should -Be 1 -Because '2.3.11.1 (L1)'
        }

        # 2.3.11.2 (L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
        Registry 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\' 'allownullsessionfallback' {
            Should -Be 0 -Because '2.3.11.2 (L1)'
        }

        # 2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
        Registry 'HKLM:\System\CurrentControlSet\Control\Lsa\pku2u\' 'AllowOnlineID' {
            Should -Be 0 -Because '2.3.11.3 (L1)'
        }

        # 2.3.11.4 (L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'RC4_HMAC_MD5, AES128_HMAC_SHA1,AES256_HMAC_SHA1, Future encryption types'
        Registry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\' 'SupportedEncryptionTypes' {
            Should -Be 28 -Because '2.3.11.4 (L1)'
        }

        # 2.3.11.5 (L1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'
        Registry 'HKLM:\System\CurrentControlSet\Control\Lsa\' 'NoLMHash' {
            Should -Be 1 -Because '2.3.11.5 (L1)'
        }

        # 2.3.11.6 (L1) Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'
        It 'Guest Account should be Disabled' {
            $SecurityOptions.'System Access'.'ForceLogoffWhenHourExpire' | Should -Be 1 -Because '2.3.11.6 (L1)'
        }

        # 2.3.11.7 (L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
        Registry 'HKLM:\System\CurrentControlSet\Control\Lsa\' 'LmCompatibilityLevel' {
            Should -Be 5 -Because '2.3.11.7 (L1)'
        }

        # 2.3.11.8 (L1) Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
        Registry 'HKLM:\System\CurrentControlSet\Services\LDAP\' 'LDAPClientIntegrity' {
            Should -BeIn 1,2 -Because '2.3.11.8 (L1)'
        }

        # 2.3.11.9 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
        Registry 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\' 'NTLMMinClientSec' {
            Should -Be 537395200 -Because '2.3.11.9 (L1)'
        }

        # 2.3.11.10 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
        Registry 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\' 'NTLMMinServerSec' {
            Should -Be 537395200 -Because '2.3.11.10 (L1)'
        }

        # 2.3.13.1 (L1) Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
        Registry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\' 'ShutdownWithoutLogon' {
            Should -Be 0 -Because '2.3.13.1 (L1)'
        }

        # 2.3.15.1 (L1) Ensure 'System objects: Require case insensitivity for non Windows subsystems' is set to 'Enabled'
        Registry 'HKLM:\System\CurrentControlSet\Control\Session Manager\Kernel\' 'ObCaseInsensitive' {
            Should -Be 1 -Because '2.3.15.1 (L1)'
        }

        # 2.3.15.2 (L1) Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'
        Registry 'HKLM:\System\CurrentControlSet\Control\Session Manager\' 'ProtectionMode' {
            Should -Be 1 -Because '2.3.15.2 (L1)'
        }

        # 2.3.17.1 (L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
        Registry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\' 'FilterAdministratorToken' {
            Should -Be 1 -Because '2.3.17.1 (L1)'
        }

        # 2.3.17.2 (L1) Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled'
        Registry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\' 'EnableUIADesktopToggle' {
            Should -Be 0 -Because '2.3.17.2 (L1)'
        }

        # 2.3.17.3 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'
        Registry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\' 'ConsentPromptBehaviorAdmin' {
            Should -Be 2 -Because '2.3.17.3 (L1)'
        }

        # 2.3.17.4 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
        Registry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\' 'ConsentPromptBehaviorUser' {
            Should -Be 0 -Because '2.3.17.4 (L1)'
        }

        # 2.3.17.5 (L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'
        Registry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\' 'EnableInstallerDetection' {
            Should -Be 1 -Because '2.3.17.5 (L1)'
        }

        # 2.3.17.6 (L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'
        Registry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\' 'EnableSecureUIAPaths' {
            Should -Be 1 -Because '2.3.17.6 (L1)'
        }

        # 2.3.17.7 (L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
        Registry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\' 'EnableLUA' {
            Should -Be 1 -Because '2.3.17.7 (L1)'
        }

        # 2.3.17.8 (L1) Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'
        Registry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\' 'PromptOnSecureDesktop' {
            Should -Be 1 -Because '2.3.17.8 (L1)'
        }

        # 2.3.17.9 (L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
        Registry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\' 'EnableVirtualization' {
            Should -Be 1 -Because '2.3.17.9 (L1)'
        }
    }

    Context 'Registry Settings' {
        # 18.9.10.1.1 (L1) Ensure 'Use enhanced anti-spoofing when available' is set to 'Enabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Biometrics\FacialFeatures' 'EnhancedAntiSpoofing' {
            Should -Be 1 -Because '18.9.10.1.1 (L1)'
        }
        
        # 18.1.2.1 (L1) Ensure 'Allow Input Personalization' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\InputPersonalization' 'AllowInputPersonalization' {
            Should -Be 0 -Because '18.1.2.1 (L1)'
        }

        # 18.9.53.1 (L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds' 'DisableEnclosureDownload' {
            Should -Be 1 -Because '18.9.53.1 (L1)'
        }

        # 18.9.41.3 (L1) Ensure 'Configure cookies' is set to 'Enabled: Block only 3rd-party cookies' or higher
        Registry 'HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Main' 'Cookies' {
            Should -Be 1 -Because '18.9.41.3 (L1)'
        }
        
        # 18.9.41.4 (L1) Ensure 'Configure Password Manager' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Main' 'FormSuggest Passwords' {
            Should -Be 'no' -Because '18.9.41.4 (L1)'
        }

        # 18.9.41.6 (L1) Ensure 'Configure search suggestions in Address bar' is set to 'Disabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\MicrosoftEdge\SearchScopes' 'ShowSearchSuggestionsGlobal' {
            Should -Be 0 -Because '18.9.41.6 (L1)'
        }

        # 18.9.41.7 (L1) Ensure 'Configure SmartScreen Filter' is set to 'Enabled'
        Registry 'HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter' 'EnabledV9' {
            Should -Be 1 -Because '18.9.41.7 (L1)'
        }

        # 18.9.13.1 (L1) Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures' {
            Should -Be 1 -Because '18.9.13.1 (L1)'
        }

        # 18.9.14.1 (L1) Ensure 'Require pin for pairing' is set to 'Enabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\Connect' 'RequirePinForPairing' {
            Should -Be 1 -Because '18.9.14.1 (L1)'
        }

        # 18.9.15.1 (L1) Ensure 'Do not display the password reveal button' is set to 'Enabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\CredUI' 'DisablePasswordReveal' {
            Should -Be 1 -Because '18.9.15.1 (L1)'
        }

        # 18.9.16.1 (L1) Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' {
            Should -Be 0 -Because '18.9.16.1 (L1)'
        }

        # 18.9.16.3 (L1) Ensure 'Do not show feedback notifications' is set to 'Enabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection' 'DoNotShowFeedbackNotifications' {
            Should -Be 1 -Because '18.9.16.3 (L1)'
        }

        # 18.9.26.1.1 (L1) Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application' 'Retention' {
            Should -Be 0 -Because '18.9.26.1.1 (L1)'
        }

        # 18.9.26.1.2 (L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application' 'MaxSize' {
            Should -BeGreaterOrEqual 32768 -Because '18.9.26.1.2 (L1)'
        }

        # 18.9.26.2.1 (L1) Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security' 'Retention' {
            Should -Be 0 -Because '18.9.26.2.1 (L1)'
        }

        # 18.9.26.2.2 (L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security' 'MaxSize' {
            Should -BeGreaterOrEqual 196608 -Because '18.9.26.2.2 (L1)'
        }

        # 18.9.26.3.1 (L1) Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup' 'Retention' {
            Should -Be 0 -Because '18.9.26.3.1 (L1)'
        }

        # 18.9.26.3.2 (L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup' 'MaxSize' {
            Should -BeGreaterOrEqual 32768 -Because '18.9.26.3.2 (L1)'
        }

        # 18.9.26.4.1 (L1) Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\System' 'Retention' {
            Should -Be 0 -Because '18.9.26.4.1 (L1)'
        }

        # 18.9.26.4.2 (L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\System' 'MaxSize' {
            Should -BeGreaterOrEqual 32768 -Because '18.9.26.4.2 (L1)'
        }

        # 18.9.8.1 (L1) Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\Explorer' 'NoAutoplayfornonVolume' {
            Should -Be 1 -Because '18.9.8.1 (L1)'
        }

        # 18.9.30.3 (L1) Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\Explorer' 'NoDataExecutionPrevention' {
            Should -Be 0 -Because '18.9.30.3 (L1)'
        }

        # 18.9.30.4 (L1) Ensure 'Turn off heap termination on corruption' is set to 'Disabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\Explorer' 'NoHeapTerminationOnCorruption' {
            Should -Be 0 -Because '18.9.30.4 (L1)'
        }

        # 18.8.19.2 (L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' 'NoBackgroundPolicy' {
            Should -Be 0 -Because '18.8.19.2 (L1)'
        }

        # 18.8.19.3 (L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' 'NoGPOListChanges' {
            Should -Be 1 -Because '18.8.19.3 (L1)'
        }

        # 18.9.74.1 (L1) Ensure 'Allow user control over installs' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\Installer' 'EnableUserControl' {
            Should -Be 0 -Because '18.9.74.1 (L1)'
        }

        # 18.9.74.2 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' {
            Should -Be 0 -Because '18.9.74.2 (L1)'
        }

        # 18.4.8.1 (L1) Ensure 'Enable insecure guest logons' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation' 'AllowInsecureGuestAuth' {
            Should -Be 0 -Because '18.4.8.1 (L1)'
        }

        # 18.4.11.2 (L1) Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\Network Connections' 'NC_AllowNetBridge_NLA' {
            Should -Be 0 -Because '18.4.11.2 (L1)'
        }

        # 18.4.11.3 (L1) Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\Network Connections' 'NC_ShowSharedAccessUI' {
            Should -Be 0 -Because '18.4.11.3 (L1)'
        }

        # 18.4.11.4 (L1) Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\Network Connections' 'NC_StdDomainUserSetLocation' {
            Should -Be 1 -Because '18.4.11.4 (L1)'
        }

        # 18.4.14.1 (L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' '\\*\NETLOGON' {
            Should -Be 'RequireMutualAuthentication=1,RequireIntegrity=1' -Because '18.4.14.1 (L1)'
        }

        # 18.4.14.1 (L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' '\\*\SYSVOL' {
            Should -Be 'RequireMutualAuthentication=1,RequireIntegrity=1' -Because '18.4.14.1 (L1)'
        }

        # 18.9.47.1 (L1) Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\OneDrive' 'DisableFileSyncNGSC' {
            Should -Be 1 -Because '18.9.47.1 (L1)'
        }

        # 18.1.1.1 (L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\Personalization' 'NoLockScreenCamera' {
            Should -Be 1 -Because '18.1.1.1 (L1)'
        }

        # 18.1.1.2 (L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\Personalization' 'NoLockScreenSlideshow' {
            Should -Be 1 -Because '18.1.1.2 (L1)'
        }

        # 18.9.84.1 (L1) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' {
            Should -Be 0 -Because '18.9.84.1 (L1)'
        }

        # 18.9.84.1 (L1) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockInvocationLogging' {
            Should -Be ' ' -Because '18.9.84.1 (L1)'
        }

        # 18.9.84.2 (L1) Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'         
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting' {
            Should -Be 0 -Because '18.9.84.2 (L1)'
        }

        # 18.9.84.1 (L1) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' 'OutputDirectory' {
            Should -Be ' ' -Because '18.9.84.1 (L1)'
        }

        # 18.9.84.1 (L1) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableInvocationHeader' {
            Should -Be ' ' -Because '18.9.84.1 (L1)'
        }

        # 18.9.16.2 (L1) Ensure 'Disable pre-release features or settings' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds' 'EnableConfigFlighting' {
            Should -Be 0 -Because '18.9.16.2 (L1)'
        }

        # 18.9.16.2 (L1) Ensure 'Disable pre-release features or settings' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds' 'EnableExperimentation' {
            Should -Be ' ' -Because '18.9.16.2 (L1)'
        }

        # 18.9.16.2 (L1) Ensure 'Disable pre-release features or settings' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds' 'AllowBuildPreview' {
            Should -Be 0 -Because '18.9.16.2 (L1)'
        }

        # 18.8.19.4 (L1) Ensure 'Continue experiences on this device' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\System' 'EnableCdp' {
            Should -Be 0 -Because '18.8.19.4 (L1)'
        }

        # 18.8.25.1 (L1) Ensure 'Block user from showing account details on signin' is set to 'Enabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\System' 'BlockUserFromShowingAccountDetailsOnSignin' {
            Should -Be 1 -Because '18.8.25.1 (L1)'
        }

        # 18.8.25.2 (L1) Ensure 'Do not display network selection UI' is set to 'Enabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\System' 'DontDisplayNetworkSelectionUI' {
            Should -Be 1 -Because '18.8.25.2 (L1)'
        }

        # 18.8.25.3 (L1) Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\System' 'DontEnumerateConnectedUsers' {
            Should -Be 1 -Because '18.8.25.3 (L1)'
        }

        # 18.8.25.4 (L1) Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\System' 'EnumerateLocalUsers' {
            Should -Be 0 -Because '18.8.25.4 (L1)'
        }
        
        # 18.8.25.5 (L1) Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\System' 'DisableLockScreenAppNotifications' {
            Should -Be 1 -Because '18.8.25.5 (L1)'
        }

        # 18.8.25.6 (L1) Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\System' 'AllowDomainPINLogon' {
            Should -Be 0 -Because '18.8.25.6 (L1)'
        }

        # 18.9.30.2 (L1) Ensure 'Configure Windows SmartScreen' is set to 'Enabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\System' 'EnableSmartScreen' {
            Should -Be 1 -Because '18.9.30.2 (L1)'
        }

        # 18.4.21.1 (L1) Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' 'fMinimizeConnections' {
            Should -Be 1 -Because '18.4.21.1 (L1)'
        }

        # 18.9.54.2 (L1) Ensure 'Allow Cortana' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search' 'AllowCortana' {
            Should -Be 0 -Because '18.9.54.2 (L1)'
        }

        # 18.9.54.3 (L1) Ensure 'Allow Cortana above lock screen' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search' 'AllowCortanaAboveLock' {
            Should -Be 0 -Because '18.9.54.3 (L1)'
        }

        # 18.9.54.4 (L1) Ensure 'Allow indexing of encrypted files' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search' 'AllowIndexingEncryptedStoresOrItems' {
            Should -Be 0 -Because '18.9.54.4 (L1)'
        }

        # 18.9.54.5 (L1) Ensure 'Allow search and Cortana to use location' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search' 'AllowSearchToUseLocation' {
            Should -Be 0 -Because '18.9.54.5 (L1)'
        }

        # 18.9.90.2 (L1) Ensure 'Configure Automatic Updates' is set to 'Enabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate' {
            Should -Be 0 -Because '18.9.90.2 (L1)'
        }

        # 18.9.90.2 (L1) Ensure 'Configure Automatic Updates' is set to 'Enabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' 'AUOptions' {
            Should -Be 5 -Because '18.9.90.2 (L1)'
        }

        # 18.9.90.2 (L1) Ensure 'Configure Automatic Updates' is set to 'Enabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' 'AutomaticMaintenanceEnabled' {
            Should -Be ' ' -Because '18.9.90.2 (L1)'
        }

        # 18.9.90.3 (L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' 'ScheduledInstallDay' {
            Should -Be 0 -Because '18.9.90.3 (L1)'
        }

        # 18.9.90.3 (L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' 'ScheduledInstallTime' {
            Should -Be 3 -Because '18.9.90.3 (L1)'
        }

        # 18.9.90.3 (L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' 'AllowMUUpdateService' {
            Should -Be ' ' -Because '18.9.90.3 (L1)'
        }

        # 18.9.90.4 (L1) Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoRebootWithLoggedOnUsers' {
            Should -Be 0 -Because '18.9.90.4 (L1)'
        }

        # 18.9.90.1.1 (L1) Ensure 'Select when Feature Updates are received' is set to 'Enabled: Current Branch for Business, 180 days'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' 'DeferFeatureUpdates' {
            Should -Be 1 -Because '18.9.90.1.1 (L1)'
        }

        # 18.9.90.1.1 (L1) Ensure 'Select when Feature Updates are received' is set to 'Enabled: Current Branch for Business, 180 days'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' 'BranchReadinessLevel' {
            Should -Be 32 -Because '18.9.90.1.1 (L1)'
        }

        # 18.9.90.1.1 (L1) Ensure 'Select when Feature Updates are received' is set to 'Enabled: Current Branch for Business, 180 days'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' 'DeferFeatureUpdatesPeriodInDays' {
            Should -Be 180 -Because '18.9.90.1.1 (L1)'
        }

        # 18.9.90.1.1 (L1) Ensure 'Select when Feature Updates are received' is set to 'Enabled: Current Branch for Business, 180 days'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' 'PauseFeatureUpdatesStartTime' {
            Should -Be '' -Because '18.9.90.1.1 (L1)'
        }

        # 18.9.90.1.2 (L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' 'DeferQualityUpdates' {
            Should -Be 1 -Because '18.9.90.1.2 (L1)'
        }

        # 18.9.90.1.2 (L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' 'DeferQualityUpdatesPeriodInDays' {
            Should -Be 0 -Because '18.9.90.1.2 (L1)'
        }

        # 18.9.90.1.2 (L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' 'PauseQualityUpdatesStartTime' {
            Should -Be '' -Because '18.9.90.1.2 (L1)'
        }

        # 18.9.86.1.1 (L1) Ensure 'Allow Basic authentication' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client' 'AllowBasic' {
            Should -Be 0 -Because '18.9.86.1.1 (L1)'
        }

        # 18.9.86.1.2 (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client' 'AllowUnencryptedTraffic' {
            Should -Be 0 -Because '18.9.86.1.2 (L1)'
        }

        # 18.9.86.1.3 (L1) Ensure 'Disallow Digest authentication' is set to 'Enabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client' 'AllowDigest' {
            Should -Be 0 -Because '18.9.86.1.3 (L1)'
        }

        # 18.9.86.2.1 (L1) Ensure 'Allow Basic authentication' is set to 'Disabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service' 'AllowBasic' {
            Should -Be 0 -Because '18.9.86.2.1 (L1)'
        }

        # 18.9.86.2.3 (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service' 'AllowUnencryptedTraffic' {
            Should -Be 0 -Because '18.9.86.2.3 (L1)'
        }

        # 18.9.86.2.4 (L1) Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service' 'DisableRunAs' {
            Should -Be 1 -Because '18.9.86.2.4 (L1)'
        }

        # 18.4.4.2 (L1) Ensure 'Turn off multicast name resolution' is set to 'Enabled' (MS Only) 
        Registry 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' {
            Should -Be 0 -Because '18.4.4.2 (L1)'
        }

        # 18.8.26.1 (L1) Ensure 'Untrusted Font Blocking' is set to 'Enabled: Block untrusted fonts and log events'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows NT\MitigationOptions' 'MitigationOptions_FontBocking' {
            Should -Be '1000000000000' -Because '18.8.26.1 (L1)'
        }

        # 18.8.32.1 (L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only)
        Registry 'HKLM:\Software\Policies\Microsoft\Windows NT\Rpc' 'EnableAuthEpResolution' {
            Should -Be 1 -Because '18.8.32.1 (L1)'
        }

        # 18.9.52.2.2 (L1) Ensure 'Do not allow passwords to be saved' is set to 'Enabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' 'DisablePasswordSaving' {
            Should -Be 1 -Because '18.9.52.2.2 (L1)'
        }

        # 18.9.52.3.3.2 (L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' 'fDisableCdm' {
            Should -Be 1 -Because '18.9.52.3.3.2 (L1)'
        }

        # 18.9.52.3.9.3 (L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' 'MinEncryptionLevel' {
            Should -Be 3 -Because '18.9.52.3.9.3 (L1)'
        }

        # 18.9.52.3.9.2 (L1) Ensure 'Require secure RPC communication' is set to 'Enabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' 'fEncryptRPCTraffic' {
            Should -Be 1 -Because '18.9.52.3.9.2 (L1)'
        }

        # 18.9.52.3.9.1 (L1) Ensure 'Always prompt for password upon connection' is set to 'Enabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' 'fPromptForPassword' {
            Should -Be 1 -Because '18.9.52.3.9.1 (L1)'
        }

        # 18.9.52.3.11.1 (L1) Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' 'DeleteTempDirsOnExit' {
            Should -Be 1 -Because '18.9.52.3.11.1 (L1)'
        }

        # 18.9.52.3.11.2 (L1) Ensure 'Do not use temporary folders per session' is set to 'Disabled'
        Registry 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' 'PerSessionTempDir' {
            Should -Be 1 -Because '18.9.52.3.11.2 (L1)'
        }

        # 9.1.7 (L1) Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' 'LogFilePath' {
            Should -Be '%systemroot%\system32\logfiles\firewall\domainfw.log' -Because '9.1.7 (L1)'
        }

        # 9.1.8 (L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' 'LogFileSize' {
            Should -BeGreaterOrEqual 16384 -Because '9.1.8 (L1)'
        }

        # 9.1.9 (L1) Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' 'LogDroppedPackets' {
            Should -Be 1 -Because '9.1.9 (L1)'
        }

        # 9.1.10 (L1) Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes' 
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' 'LogSuccesssfulConnections' {
            Should -Be 1 -Because '9.1.10 (L1)'
        }

        # 9.1.1 (L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile' 'EnableFirewall' {
            Should -Be 1 -Because '9.1.1 (L1)'
        }

        # 9.1.3 (L1) Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile' 'DefaultOutboundAction' {
            Should -Be 0 -Because '9.1.3 (L1)'
        }

        # 9.1.2 (L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile' 'DefaultInboundAction' {
            Should -Be 1 -Because '9.1.2 (L1)'
        }

        # 9.1.4 (L1) Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile' 'DisableNotifications' {
            Should -Be 1 -Because '9.1.4 (L1)'
        }

        # 9.1.5 (L1) Ensure 'Windows Firewall: Domain: Settings: Apply local firewall rules' is set to 'Yes (default)'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile' 'AllowLocalPolicyMerge' {
            Should -Be 1 -Because '9.1.5 (L1)'
        }

        # 9.1.6 (L1) Ensure 'Windows Firewall: Domain: Settings: Apply local connection security rules' is set to 'Yes (default)'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile' 'AllowLocalIPsecPolicyMerge' {
            Should -Be 1 -Because '9.1.6 (L1)'
        }

        # 9.2.7 (L1) Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' 'LogFilePath' {
            Should -Be '%systemroot%\system32\logfiles\firewall\privatefw.log' -Because '9.2.7 (L1)'
        }

        # 9.2.8 (L1) Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' 'LogFileSize' {
            Should -BeGreaterOrEqual 16384 -Because '9.2.8 (L1)'
        }

        # 9.2.9 (L1) Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' 'LogDroppedPackets' {
            Should -Be 1 -Because '9.2.9 (L1)'
        }

        # 9.2.10 (L1) Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' 'LogSuccesssfulConnections' {
            Should -Be 1 -Because 'rule (L1)'
        }

        # 9.2.4 (L1) Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No' 
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile' 'DisableNotifications' {
            Should -Be 1 -Because '9.2.4 (L1)'
        }

        # 9.2.5 (L1) Ensure 'Windows Firewall: Private: Settings: Apply local firewall rules' is set to 'Yes (default)'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile' 'AllowLocalPolicyMerge' {
            Should -Be 1 -Because '9.2.5 (L1)'
        }

        # 9.2.6 (L1) Ensure 'Windows Firewall: Private: Settings: Apply local connection security rules' is set to 'Yes (default)'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile' 'AllowLocalIPsecPolicyMerge' {
            Should -Be 1 -Because '9.2.6 (L1)'
        }

        # 9.2.1 (L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile' 'EnableFirewall' {
            Should -Be 1 -Because '9.2.1 (L1)'
        }

        # 9.2.3 (L1) Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile' 'DefaultOutboundAction' {
            Should -Be 0 -Because '9.2.3 (L1)'
        }
        
        # 9.2.2 (L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile' 'DefaultInboundAction' {
            Should -Be 1 -Because '9.2.2 (L1)'
        }

        # 9.3.7 (L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' 'LogFilePath' {
            Should -Be '%systemroot%\system32\logfiles\firewall\publicfw.log' -Because '9.3.7 (L1)'
        }
        
        # 9.3.8 (L1) Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' 'LogFileSize' {
            Should -BeGreaterOrEqual 16384 -Because '9.3.8 (L1)'
        }

        # 9.3.9 (L1) Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' 'LogDroppedPackets' {
            Should -Be 1 -Because '9.3.9 (L1)'
        }
        
        # 9.3.10 (L1) Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' 'LogSuccesssfulConnections' {
            Should -Be 1 -Because '9.3.10 (L1)'
        }

        # 9.3.4 (L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'Yes'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile' 'DisableNotifications' {
            Should -Be 0 -Because '9.3.4 (L1)'
        }
        
        # 9.3.5 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile' 'AllowLocalPolicyMerge' {
            Should -Be 0 -Because '9.3.5 (L1)'
        }

        # 9.3.6 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile' 'AllowLocalIPsecPolicyMerge' {
            Should -Be 0 -Because '9.3.6 (L1)'
        }
        
        # 9.3.1 (L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile' 'EnableFirewall' {
            Should -Be 1 -Because '9.3.1 (L1)'
        }

        # 9.3.3 (L1) Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile' 'DefaultOutboundAction' {
            Should -Be 0 -Because '9.3.3 (L1)'
        }

        # 9.3.2 (L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile' 'DefaultInboundAction' {
            Should -Be 1 -Because '9.3.2 (L1)'
        }

        # 18.9.73.2 (L1) Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On'
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace' 'AllowWindowsInkWorkspace' {
            Should -Be 1 -Because '18.9.73.2 (L1)'
        }

        # 18.9.61.2 (L1) Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsStore' 'AutoDownload' {
            Should -Be 4 -Because '18.9.61.2 (L1)'
        }

        # 18.9.61.3 (L1) Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled' 
        Registry 'HKLM:\Software\Policies\Microsoft\WindowsStore' 'DisableOSUpgrade' {
            Should -Be 1 -Because '18.9.61.3 (L1)'
        }

        # 18.2.2 (L1) Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled' (MS only)
        Registry 'HKLM:\Software\Policies\Microsoft Services\AdmPwd' 'PwdExpirationProtectionEnabled' {
            Should -Be 1 -Because '18.2.2 (L1)'
        }

        # # 18.2.3 (L1) Ensure 'Enable Local Admin Password Management' is set to 'Enabled' (MS only)
        Registry 'HKLM:\Software\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled' {
            Should -Be 1 -Because '18.2.3 (L1)'
        }

        # 18.2.4 (L1) Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters' (MS only)
        Registry 'HKLM:\Software\Policies\Microsoft Services\AdmPwd' 'PasswordComplexity' {
            Should -Be 4 -Because '18.2.4 (L1)'
        }

        # 18.2.5 (L1) Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more' (MS only)
        Registry 'HKLM:\Software\Policies\Microsoft Services\AdmPwd' 'PasswordLength' {
            Should -BeGreaterOrEqual 15 -Because '18.2.5 (L1)'
        }

        # 18.2.6 (L1) Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer' (MS only)
        Registry 'HKLM:\Software\Policies\Microsoft Services\AdmPwd' 'PasswordAgeDays' {
            Should -BeLessOrEqual 30 -Because '18.2.6 (L1)'
        }

        # 18.3.1 (L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'
        Registry 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon' {
            Should -Be '0' -Because '18.3.1 (L1)'
        }

        # 18.8.31.2 (L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled' 
        Registry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowToGetHelp' {
            Should -Be '0' -Because '18.8.31.2 (L1)'
        }

        # 18.8.31.1 (L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
        Registry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowUnsolicited' {
            Should -Be '0' -Because '18.8.31.1 (L1)'
        }

        # 18.3.9 (L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'
        Registry 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'ScreenSaverGracePeriod' {
            Should -Be '5' -Because '18.3.9 (L1)'
        }
    }

    Context 'Audit Policy' {
        AuditPolicy 'Account Logon' 'Credential Validation' {
            Should -Be 'Success and Failure' -Because '17.1.1 (L1)'
        }

        AuditPolicy 'Account Management' 'Application Group Management' {
            Should -Be 'Success and Failure' -Because '17.2.1 (L1)'
        }

        AuditPolicy 'Account Management' 'Computer Account Management' {
            Should -Be 'Success and Failure' -Because '17.2.2 (L1)'
        }

        AuditPolicy 'Account Management' 'Other Account Management Events' {
            Should -Be 'Success and Failure' -Because '17.2.4 (L1)'
        }

        AuditPolicy 'Account Management' 'Security Group Management' {
            Should -Be 'Success and Failure' -Because '17.2.5 (L1)'
        }

        AuditPolicy 'Account Management' 'User Account Management' {
            Should -Be 'Success and Failure' -Because '17.2.6 (L1)'
        }

        AuditPolicy 'Detailed Tracking' 'Plug and Play Events' {
            Should -Be 'Success' -Because '17.3.1 (L1)'
        }

        AuditPolicy 'Detailed Tracking' 'Process Creation' {
            Should -Be 'Success' -Because '17.3.2 (L1)'
        }

        AuditPolicy 'Logon/Logoff' 'Account Lockout' {
            Should -Be 'Success and Failure' -Because '17.5.1 (L1)'
        }

        AuditPolicy 'Logon/Logoff' 'Group Membership' {
            Should -Be 'Success' -Because '17.5.2 (L1)'
        }

        AuditPolicy 'Logon/Logoff' 'Logoff' {
            Should -Be 'Success' -Because '17.5.3 (L1)'
        }

        AuditPolicy 'Logon/Logoff' 'Logon' {
            Should -Be 'Success and Failure' -Because '17.5.4 (L1)'
        }

        AuditPolicy 'Logon/Logoff' 'Other Logon/Logoff Events' {
            Should -Be 'Success and Failure' -Because '17.5.5 (L1)'
        }

        AuditPolicy 'Logon/Logoff' 'Special Logon' {
            Should -Be 'Success' -Because '17.5.6 (L1)'
        }

        AuditPolicy 'Object Access' 'Removable Storage' {
            Should -Be 'Success and Failure' -Because '17.6.1 (L1)'
        }

        AuditPolicy 'Policy Change' 'Audit Policy Change' {
            Should -Be 'Success and Failure' -Because '17.7.1 (L1)'
        }

        AuditPolicy 'Policy Change' 'Authentication Policy Change' {
            Should -Be 'Success' -Because '17.7.2 (L1)'
        }

        AuditPolicy 'Policy Change' 'Authorization Policy Change' {
            Should -Be 'Success' -Because '17.7.3 (L1)'
        }

        AuditPolicy 'Privilege Use' 'Sensitive Privilege Use' {
            Should -Be 'Success and Failure' -Because '17.8.1 (L1)'
        }

        AuditPolicy 'System' 'IPsec Driver' {
            Should -Be 'Success and Failure' -Because '17.9.1 (L1)'
        }

        AuditPolicy 'System' 'Other System Events' {
            Should -Be 'Success and Failure' -Because '17.9.2 (L1)'
        }

        AuditPolicy 'System' 'Security State Change' {
            Should -Be 'Success' -Because '17.9.3 (L1)'
        }

        AuditPolicy 'System' 'Security System Extension' {
            Should -Be 'Success and Failure' -Because '17.9.4 (L1)'
        }

        AuditPolicy 'System' 'System Integrity' {
            Should -Be 'Success and Failure' -Because '17.9.5 (L1)'
        }
    }
}