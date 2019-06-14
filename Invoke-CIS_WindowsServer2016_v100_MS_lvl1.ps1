<#
    .SYNOPSIS
        Invoke-CIS_WindowsServer2016_v100_MS_lvl1.ps1

    .DESCRIPTION
        This script performs server hardening via Desired State Configuration (DSC).

        Post-execution the configuration can be optionally validated via the following Pester script: 
        CIS_WindowsServer2016_v100_MS_lvl1.tests.ps1
#>

# Install/load Prerequisites

$RequiredModules = @(
    @{
        Name = 'NetworkingDsc'
        MinimumVersion = [version]'6.1.0.0'
    },
    @{
        Name = 'AuditPolicyDsc'
        MinimumVersion = [version]'1.2.0.0'
    },
    @{
        Name = 'SecurityPolicyDsc'
        MinimumVersion = [version]'2.8.0.0'
    }
)

ForEach ($RequiredModule in $RequiredModules) {

    Try {
        Import-Module -Name $RequiredModule.Name -MinimumVersion $RequiredModule.MinimumVersion -ErrorAction Stop
    }
    Catch {
        $CurrentVersions = Get-Module $RequiredModule.Name -ListAvailable
        if (($CurrentVersions).Count -ge 1) {
            $CurrentVersions | Uninstall-Module -Force
        }
        Install-Module @RequiredModule -Force
    }

    Import-Module -Name $RequiredModule.Name -Force
}

# Execute DSC

. .\CIS_WindowsServer2016_v100_MS_lvl1.ps1