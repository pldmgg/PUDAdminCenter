<#
    .SYNOPSIS
        Use PowerShell to Update PowerShell Core. If you're on Windows, this function can be used to do the initial
        install of PowerShell Core. On any other OS, a version of PowerShell Core (at least 6.0.0-beta) must already
        be installed and used to run this function.

    .DESCRIPTION
        See SYNOPSIS

    .PARAMETER DownloadDirectory
        OPTIONAL*
        
        This parameter takes a string that represents a full directory path that the PowerShell Core installation package
        will be downloaded to.
        
        *NOTE: This parameter becomes MANDATORY if you do NOT use the -UsePackageManagement parameter.

    .PARAMETER UsePackageManagement
        OPTIONAL*

        This parameter is a switch. If you use it, the appropriate package management system on the respective
        Operating System will be used to install PowerShell Core. This method of installation is recommended
        over direct download.

        *NOTE: This parameter becomes MANDATORY if you do NOT use the -DownloadDirectory parameter.

    .PARAMETER OS
        This parameter is OPTIONAL.

        This parameter takes a string that indicates an OS.
        
        This parameter takes a string that must be one of the following values:
        "win", "macos", "linux", "ubuntu", "debian", "centos", "redhat"

        This parameter should only be used if you are downloading a PowerShell Core release that is NOT
        meant for the Operating System that you are currently on.

    .Parameter ReleaseVersion
        This parameter is OPTIONAL.

        This parameter should only be used if you do NOT want the latest version.

        This parameter takes a string that indicates the PowerShell Core Release Version.
        Example: 6.1.0

        If the parameter is not used, the function will default to using the latest Release Version.

    .Parameter Channel
        This parameter is OPTIONAL.

        This parameter should only be used if you do NOT want the latest version.

        This parameter takes a string that can be one of 4 values:
        "beta", "rc", "stable", "preview"

        If the parameter is not used, the function will default to using the latest Channel for the
        given ReleaseVersion.

    .Parameter Iteration
        This parameter is OPTIONAL.
        
        This parameter should only be used if you do NOT want the latest version.

        This parameter takes an integer. For example, in the release "powershell-6.1.0-preview.2-1.rhel.7.x86_64.rpm",
        iteration is 2.

    .PARAMETER Latest
        This parameter is OPTIONAL.

        This parameter is a switch. It is used by default. Using this switch installs the latest release of
        PowerShell Core.
            
        This switch overrides the -ReleaseVersion, -Channel, and -Iteration parameters
        (i.e. it will be as if they were not used at all). By the same token, if you do not use any of the
        -ReleaseVersion, -Channel, and -Iteration parameters, it will be as if this switch is used.

        IMPORTANT NOTE: Sometimes Package Management repositories are ahead of
        https://github.com/PowerShell/PowerShell/releases, and sometimes they are behind. If this
        parameter is used, then it will essentially ignore the -DownloadDirectory and -UsePackageManagement
        parameters and use the install method that has the latest PowerShell Core package available.

    .EXAMPLE
        Update-PowerShellCore

    .EXAMPLE
        Update-PowerShellCore -UsePackageManagement "Yes"

    .EXAMPLE
        Update-PowerShellCore -DownloadDirectory "$HOME\Downloads"
#>
function Update-PowerShellCore {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidateSet("Windows","Linux")]
        [string]$RemoteOSGuess = "Windows",

        [Parameter(Mandatory=$True)]
        [string]$RemoteHostNameOrIP,

        [Parameter(
            Mandatory=$True,
            ParameterSetName='Local'
        )]
        [ValidatePattern("\\")] # Must be in format <RemoteHostName>\<User>
        [string]$LocalUserName,

        [Parameter(
            Mandatory=$True,
            ParameterSetName='Domain'    
        )]
        [ValidatePattern("\\")] # Must be in format <DomainShortName>\<User>
        [string]$DomainUserName,

        [Parameter(
            Mandatory=$True,
            ParameterSetName='Local'    
        )]
        [securestring]$LocalPasswordSS,

        [Parameter(
            Mandatory=$True,
            ParameterSetName='Domain'
        )]
        [securestring]$DomainPasswordSS,

        [Parameter(Mandatory=$False)]
        [string]$KeyFilePath,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Ubuntu1404","Ubuntu1604","Ubuntu1804","Ubuntu1810","Debian8","Debain9","CentOS7","RHEL7","OpenSUSE423","Fedora","Raspbian")]
        [string]$OS,

        [Parameter(Mandatory=$False)]
        [switch]$UsePackageManagement = $True,

        [Parameter(Mandatory=$False)]
        [switch]$ConfigurePSRemoting
    )

    ##### BEGIN Native Helper Functions #####

    function GetElevation {
        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or $PSVersionTable.PSVersion.Major -le 5) {
            [System.Security.Principal.WindowsPrincipal]$currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal(
                [System.Security.Principal.WindowsIdentity]::GetCurrent()
            )
    
            [System.Security.Principal.WindowsBuiltInRole]$administratorsRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    
            if($currentPrincipal.IsInRole($administratorsRole)) {
                return $true
            }
            else {
                return $false
            }
        }
        
        if ($PSVersionTable.Platform -eq "Unix") {
            if ($(whoami) -eq "root") {
                return $true
            }
            else {
                return $false
            }
        }
    }

    function Get-NativePath {
        [CmdletBinding()]
        Param( 
            [Parameter(Mandatory=$True)]
            [string[]]$PathAsStringArray
        )

        $PathAsStringArray = foreach ($pathPart in $PathAsStringArray) {
            $SplitAttempt = $pathPart -split [regex]::Escape([IO.Path]::DirectorySeparatorChar)
            
            if ($SplitAttempt.Count -gt 1) {
                foreach ($obj in $SplitAttempt) {
                    $obj
                }
            }
            else {
                $pathPart
            }
        }
        $PathAsStringArray = $PathAsStringArray -join [IO.Path]::DirectorySeparatorChar

        $PathAsStringArray
    
    }

    ##### END Native Helper Functions #####


    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

    if (!$(GetElevation)) {
        Write-Error "Please run PowerShell with elevated privileges and try again. Halting!"
        $global:FunctionResult = "1"
        return
    }

    try {
        $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $RemoteHostNameOrIP -ErrorAction Stop
    }
    catch {
        Write-Error $_
        Write-Error "Unable to resolve '$RemoteHostNameOrIP'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($LocalUserName) {
        if ($($LocalUserName -split "\\")[0] -ne $RemoteHostNetworkInfo.HostName) {
            $ErrMsg = "The HostName indicated by -LocalUserName (i.e. $($($LocalUserName -split "\\")[0]) is not the same as " +
            "the HostName as determined by network resolution (i.e. $($RemoteHostNetworkInfo.HostName))! Halting!"
            Write-Error $ErrMsg
            $global:FunctionResult = "1"
            return
        }
    }
    if ($DomainUserName) {
        if ($($DomainUserName -split "\\")[0] -ne $($RemoteHostNetworkInfo.Domain -split "\.")[0]) {
            $ErrMsg = "The Domain indicated by -DomainUserName (i.e. '$($($DomainUserName -split "\\")[0])') is not the same as " +
            "the Domain as determined by network resolution (i.e. '$($($RemoteHostNetworkInfo.Domain -split "\.")[0])')! Halting!"
            Write-Error $ErrMsg
            $global:FunctionResult = "1"
            return
        }
    }

    # Create PSCustomObjects with all applicable installation info
    $ReleaseInfo = Invoke-RestMethod https://api.github.com/repos/PowerShell/PowerShell/releases/latest
    $PSCorePackageUrls = $ReleaseInfo.assets.browser_download_url
    $PSCorePackageNames = $ReleaseInfo.assets.name
    <#
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell-6.1.0-1.rhel.7.x86_64.rpm
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell-6.1.0-linux-arm32.tar.gz
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell-6.1.0-linux-musl-x64.tar.gz
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell-6.1.0-linux-x64.tar.gz
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell-6.1.0-osx-x64.pkg
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell-6.1.0-osx-x64.tar.gz
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/PowerShell-6.1.0-win-arm32.zip
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/PowerShell-6.1.0-win-arm64.zip
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/PowerShell-6.1.0-win-x64.msi
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/PowerShell-6.1.0-win-x64.zip
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/PowerShell-6.1.0-win-x86.msi
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/PowerShell-6.1.0-win-x86.zip
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell_6.1.0-1.debian.8_amd64.deb
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell_6.1.0-1.debian.9_amd64.deb
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell_6.1.0-1.ubuntu.14.04_amd64.deb
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell_6.1.0-1.ubuntu.16.04_amd64.deb
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell_6.1.0-1.ubuntu.18.04_amd64.deb
    #>
    switch ($PSCorePackageUrls) {
        {$_ -match "ubuntu" -and $_ -match "14\.04" -and $_ -match "\.deb"} {
            $Ubuntu1404PackageUrl = $_
            $Ubuntu1404PackageName = $($_ -split '/')[-1]
        }
        {$_ -match "ubuntu" -and $_ -match "16\.04" -and $_ -match "\.deb"} {
            $Ubuntu1604PackageUrl = $_
            $Ubuntu1604PackageName = $($_ -split '/')[-1]
        }
        {$_ -match "ubuntu" -and $_ -match "18\.04" -and $_ -match "\.deb"} {
            $Ubuntu1804PackageUrl = $_
            $Ubuntu1804PackageName = $($_ -split '/')[-1]
        }
        {$_ -match "debian\.8" -and $_ -match "\.deb"} {
            $Debian8PackageUrl = $_
            $Debian8PackageName = $($_ -split '/')[-1]
        }
        {$_ -match "debian\.9" -and $_ -match "\.deb"} {
            $Debian9PackageUrl = $_
            $Debian9PackageName = $($_ -split '/')[-1]
        }
        {$_ -match "rhel\.7" -and $_ -match "\.rpm"} {
            $CentOS7PackageUrl = $RHEL7PackageUrl = $OpenSUSE423PackageUrl = $Fedora27PackageUrl = $Fedora28PackageUrl = $_
            $CentOS7PackageName = $RHEL7PackageName = $OpenSUSE423PackageName = $Fedora27PackageName = $Fedora28PackageName = $($_ -split '/')[-1]
        }
        {$_ -match "osx" -and $_ -match "\.pkg"} {
            $MacOSPackageUrl = $_
            $MacOSPackageName = $($_ -split '/')[-1]
        }
        {$_ -match "win" -and $_ -match "x64" -and $_ -match "\.msi"} {
            $Win64PackageUrl = $_
            $Win64PackageName = $($_ -split '/')[-1]
        }
        {$_ -match "win" -and $_ -match "x86" -and $_ -match "\.msi"} {
            $Win32PackageUrl = $_
            $Win32PackageName = $($_ -split '/')[-1]
        }
        {$_ -match "win" -and $_ -match "arm64" -and $_ -match "\.zip"} {
            $WinArm64PackageUrl = $_
            $WinArm64PackageName = $($_ -split '/')[-1]
        }
        {$_ -match "win" -and $_ -match "arm32" -and $_ -match "\.zip"} {
            $WinArm32PackageUrl = $_
            $WinArm32PackageName = $($_ -split '/')[-1]
        }
        {$_ -match "linux" -and $_ -match "x64" -and $_ -match "\.tag\.gz"} {
            $LinuxGenericPackageUrl = $_
            $LinuxGenericPackageName = $($_ -split '/')[-1]
        }
        {$_ -match "linux" -and $_ -match "arm32" -and $_ -match "\.tag\.gz"} {
            $LinuxGenericArmPackageUrl = $RaspbianArmPackageUrl = $_
            $LinuxGenericArmPackageName = $RaspbianArmPackageName = $($_ -split '/')[-1]
        }
    }

    # Windows Install Info
    $WindowsPMInstallScriptPrep = @(
        'try {'
        "    if (`$(Get-Module -ListAvailable).Name -notcontains 'ProgramManagement') {`$null = Install-Module ProgramManagement -ErrorAction Stop}"
        "    if (`$(Get-Module).Name -notcontains 'ProgramManagement') {`$null = Import-Module ProgramManagement -ErrorAction Stop}"
        '    Install-Program -ProgramName powershell-core -CommandName pwsh.exe'
        '}'
        'catch {'
        '    Write-Error $_'
        "    `$global:FunctionResult = '1'"
        '    return'
        '}'
    )
    $WindowsPMInstallScript = "powershell -NoProfile -Command \`"$($WindowsPMInstallScript -join '; ')\`""

    $WindowsManualInstallScriptPrep = @(
        "`$OutFilePath = Join-Path `$HOME 'Downloads\$Win64PackageName'"
        "Invoke-WebRequest -Uri $Win64PackageUrl -OutFile `$OutFilePath"
        '$DateStamp = Get-Date -Format yyyyMMddTHHmmss'
        '$MSIFullPath = $OutFilePath'
        '$MSIParentDir = $MSIFullPath | Split-Path -Parent'
        '$MSIFileName = $MSIFullPath | Split-Path -Leaf'
        "`$MSIFileNameOnly = `$MSIFileName -replace [regex]::Escape('.msi'),''"
        "`$logFile = Join-Path `$MSIParentDir (`$MSIFileNameOnly + `$DateStamp + '.log')"
        '$MSIArguments = @('
        "    '/i'"
        '    $MSIFullPath'
        "    '/qn'"
        "    '/norestart'"
        "    '/L*v'"
        '    $logFile'
        ')'
        'Start-Process msiexec.exe -ArgumentList $MSIArguments -Wait -NoNewWindow'
    )
    $WindowsManualInstallScript = "powershell -NoProfile -Command \`"$($WindowsManualInstallScriptPrep -join '; ')\`""

    $WindowsUninstallScript = @(
        'try {'
        '    if ($(Get-Module -ListAvailable).Name -notcontains "ProgramManagement") {$null = Install-Module ProgramManagement -ErrorAction Stop}'
        '    if ($(Get-Module).Name -notcontains "ProgramManagement") {$null = Import-Module ProgramManagement -ErrorAction Stop}'
        '    Install-Program -ProgramName powershell-core -CommandName pwsh.exe'
        '}'
        'catch {'
        '    Write-Error $_'
        '    $global:FunctionResult = "1"'
        '    return'
        '}'
        'try {'
        '    Uninstall-Program -ProgramName powershell-core -ErrorAction Stop'
        '}'
        'catch {'
        '    Write-Error $_'
        '    $global:FunctionResult = "1"'
        '    return'
        '}'
    )

    $WindowsPwshRemotingScript = @(
        'try {'
        "    if (`$(Get-Module -ListAvailable).Name -notcontains 'WinSSH') {`$null = Install-Module WinSSH -ErrorAction Stop}"
        "    if (`$(Get-Module).Name -notcontains 'WinSSH') {`$null = Import-Module WinSSH -ErrorAction Stop}"
        '    Install-WinSSH -GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell pwsh'
        '}'
        'catch {'
        '    Write-Error $_'
        "    `$global:FunctionResult = '1'"
        '    return'
        '}'
    )

    $Windows = [pscustomobject]@{
        PackageManagerInstallScript = $WindowsPMInstallScript
        ManualInstallScript         = $WindowsManualInstallScript
        UninstallScript             = $WindowsUninstallScript
        ConfigurePwshRemotingScript = $WindowsPwshRemotingScript
    }
    
    # Ubuntu 14.04 Install Info
    $Ubuntu1404PMInstallScriptPrep = @(
        'wget -q https://packages.microsoft.com/config/ubuntu/14.04/packages-microsoft-prod.deb'
        'dpkg -i packages-microsoft-prod.deb'
        'apt update'
        'apt install -y powershell'
    )
    $Ubuntu1404PMInstallScript = "sudo bash -c `"$($Ubuntu1404PMInstallScript -join '; ')`""

    $Ubuntu1404ManualInstallScriptPrep = @(
        "wget -q $Ubuntu1404PackageUrl"
        "dpkg -i $Ubuntu1404PackageName"
        'apt install -f'
    )
    $Ubuntu1404ManualInstallScript = "sudo bash -c `"$($Ubuntu1404ManualInstallScriptPrep -join '; ')`""

    $Ubuntu1404UninstallScript = 'sudo apt remove powershell'

    $Ubuntu1404 = [pscustomobject]@{
        PackageManagerInstallScript = $Ubuntu1404PMInstallScript
        ManualInstallScript         = $Ubuntu1404ManualInstallScript
        UninstallScript             = $Ubuntu1404UninstallScript
    }

    # Ubuntu 16.04 Install Info
    $Ubuntu1604PMInstallScriptPrep = @(
        'wget -q https://packages.microsoft.com/config/ubuntu/16.04/packages-microsoft-prod.deb'
        'dpkg -i packages-microsoft-prod.deb'
        'apt update'
        'apt install -y powershell'
    )
    $Ubuntu1604PMInstallScript = "sudo bash -c `"$($Ubuntu1604PMInstallScript -join '; ')`""

    $Ubuntu1604ManualInstallScriptPrep = @(
        "wget -q $Ubuntu1604PackageUrl"
        "dpkg -i $Ubuntu1604PackageName"
        'apt install -f'
    )
    $Ubuntu1604ManualInstallScript = "sudo bash -c `"$($Ubuntu1604ManualInstallScriptPrep -join '; ')`""

    $Ubuntu1604UninstallScript = 'sudo apt remove powershell'

    $Ubuntu1604 = [pscustomobject]@{
        PackageManagerInstallScript = $Ubuntu1604PMInstallScript
        ManualInstallScript         = $Ubuntu1604ManualInstallScript
        UninstallScript             = $Ubuntu1604UninstallScript
    }

    # Ubuntu 18.04 Install Info
    $Ubuntu1804PMInstallScriptPrep = @(
        'wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb'
        'dpkg -i packages-microsoft-prod.deb'
        'apt update'
        'apt install -y powershell'
    )
    $Ubuntu1804PMInstallScript = "sudo bash -c `"$($Ubuntu1804PMInstallScript -join '; ')`""

    $Ubuntu1804ManualInstallScriptPrep = @(
        "wget -q $Ubuntu1804PackageUrl"
        "dpkg -i $Ubuntu1804PackageName"
        'apt install -f'
    )
    $Ubuntu1804ManualInstallScript = "sudo bash -c `"$($Ubuntu1804ManualInstallScriptPrep -join '; ')`""

    $Ubuntu1804UninstallScript = 'sudo apt remove powershell'

    $Ubuntu1804 = [pscustomobject]@{
        PackageManagerInstallScript = $Ubuntu1804PMInstallScript
        ManualInstallScript         = $Ubuntu1804ManualInstallScript
        UninstallScript             = $Ubuntu1804UninstallScript
    }

    # Debian 8 Install Info
    $Debian8PMInstallScriptPrep = @(
        'apt update'
        'apt install curl apt-transport-https'
        'curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -'
        "sh -c 'echo `"deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-jessie-prod jessie main`" > /etc/apt/sources.list.d/microsoft.list'"
        'apt update'
        'apt install -y powershell'
    )
    $Debian8PMInstallScript = "sudo bash -c `"$($Debain8PMInstallScript -join '; ')`""

    $Debian8ManualInstallScriptPrep = @(
        "wget -q $Debian8PackageUrl"
        "dpkg -i $Debian8PackageName"
        'apt install -f'
    )
    $Debian8ManualInstallScript = "sudo bash -c `"$($Debian8ManualInstallScriptPrep -join '; ')`""

    $Debian8UninstallScript = 'sudo apt remove powershell'

    $Debian8 = [pscustomobject]@{
        PackageManagerInstallScript = $Debian8PMInstallScript
        ManualInstallScript         = $Debian8ManualInstallScript
        UninstallScript             = $Debian8UninstallScript
    }

    # Debian 9 Install Info
    $Debian9PMInstallScriptPrep = @(
        'apt update'
        'apt install install curl gnupg apt-transport-https'
        'curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -'
        "sh -c 'echo `"deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main`" > /etc/apt/sources.list.d/microsoft.list'"
        'apt update'
        'apt install -y powershell'
    )
    $Debian9PMInstallScript = "sudo bash -c `"$($Debain9PMInstallScript -join '; ')`""

    $Debian9ManualInstallScriptPrep = @(
        "wget -q $Debian9PackageUrl"
        "dpkg -i $Debian9PackageName"
        'apt install -f'
    )
    $Debian9ManualInstallScript = "sudo bash -c `"$($Debian9ManualInstallScriptPrep -join '; ')`""

    $Debian9UninstallScript = 'sudo apt remove powershell'

    $Debian9 = [pscustomobject]@{
        PackageManagerInstallScript = $Debian9PMInstallScript
        ManualInstallScript         = $Debian9ManualInstallScript
        UninstallScript             = $Debian9UninstallScript
    }

    # CentOS 7 and RHEL 7 Install Info
    $CentOS7PMInstallScriptPrep = $RHELPMInstallScriptPrep = @(
        'curl https://packages.microsoft.com/config/rhel/7/prod.repo | sudo tee /etc/yum.repos.d/microsoft.repo'
        'yum install -y powershell'
    )
    $CentOS7PMInstallScript = $RHEL7PMInstallScript = "sudo bash -c `"$($CentOS7PMInstallScript -join '; ')`""

    $CentOS7ManualInstallScriptPrep = $RHEL7ManualInstallScriptPrep = @(
        "yum install $CentOS7PackageUrl"
    )
    $CentOS7ManualInstallScript = $RHEL7ManualInstallScript = "sudo bash -c `"$($CentOS7ManualInstallScriptPrep -join '; ')`""

    $CentOS7UninstallScript = $RHEL7UninstallScript = 'sudo yum remove powershell'

    $CentOS7 = $RHEL7 = [pscustomobject]@{
        PackageManagerInstallScript = $CentOS7PMInstallScript
        ManualInstallScript         = $CentOS7ManualInstallScript
        UninstallScript             = $CentOS7UninstallScript
    }

    # OpenSUSE 42.3 Install Info
    $OpenSUSE423PMInstallScriptPrep = @(
        'rpm --import https://packages.microsoft.com/keys/microsoft.asc'
        'zypper ar https://packages.microsoft.com/rhel/7/prod/'
        'zypper update'
        'zypper install powershell'
    )
    $OpenSUSE423PMInstallScript = "sudo bash -c `"$($OpenSUSE423PMInstallScript -join '; ')`""

    $OpenSUSE423ManualInstallScriptPrep = @(
        'rpm --import https://packages.microsoft.com/keys/microsoft.asc'
        "zypper install $OpenSUSE423PackageUrl"
    )
    $OpenSUSE423ManualInstallScript = "sudo bash -c `"$($OpenSUSE423ManualInstallScriptPrep -join '; ')`""

    $OpenSUSE423UninstallScript = 'sudo zypper remove powershell'

    $OpenSUSE423 = [pscustomobject]@{
        PackageManagerInstallScript = $OpenSUSE423PMInstallScript
        ManualInstallScript         = $OpenSUSE423ManualInstallScript
        UninstallScript             = $OpenSUSE423UninstallScript
    }

    # Fedora Install Info
    $FedoraPMInstallScriptPrep = @(
        'rpm --import https://packages.microsoft.com/keys/microsoft.asc'
        'curl https://packages.microsoft.com/config/rhel/7/prod.repo | sudo tee /etc/yum.repos.d/microsoft.repo'
        'dnf update'
        'dnf install compat-openssl10'
        'dnf install -y powershell'
    )
    $FedoraPMInstallScript = "sudo bash -c `"$($FedoraPMInstallScript -join '; ')`""

    $FedoraManualInstallScriptPrep = @(
        'dnf install compat-openssl10'
        "dnf install $FedoraPackageUrl"
    )
    $FedoraManualInstallScript = "sudo bash -c `"$($FedoraManualInstallScriptPrep -join '; ')`""

    $FedoraUninstallScript = 'sudo dnf remove powershell'

    $Fedora = [pscustomobject]@{
        PackageManagerInstallScript = $FedoraPMInstallScript
        ManualInstallScript         = $FedoraManualInstallScript
        UninstallScript             = $FedoraUninstallScript
    }

    # Raspbian Install Info
    $RaspbianManualInstallScriptPrep = @(
        'apt install libunwind8'
        "wget -q $LinuxGenericArmPackageUrl"
        'mkdir ~/powershell'
        "tar -xvf ./$LinuxGenericArmPackageName -C ~/powershell"
    )
    $RaspbianManualInstallScript = "sudo bash -c `"$($RaspbianManualInstallScriptPrep -join '; ')`""

    $RaspbianUninstallScript = 'rm -rf ~/powershell'

    $Raspbian = [pscustomobject]@{
        PackageManagerInstallScript = $null
        ManualInstallScript         = $RaspbianManualInstallScript
        UninstallScript             = $RaspbianUninstallScript
    }

    # Probe the Remote Host to get OS and Shell Info
    try {
        $GetSSHProbeSplatParams = @{
            RemoteHostNameOrIP  = $RemoteHostNameOrIP
        }
        if ($DomainUserName -and $DomainPasswordSS) {
            $GetSSHProbeSplatParams.Add("DomainUserName",$DomainUserName)
            $GetSSHProbeSplatParams.Add("DomainPasswordSS",$DomainPasswordSS)
        }
        if ($LocalUserName -and $LocalPasswordSS) {
            $GetSSHProbeSplatParams.Add("LocalUserName",$LocalUserName)
            $GetSSHProbeSplatParams.Add("LocalPasswordSS",$LocalPasswordSS)
        }
        if ($KeyFilePath) {
            $GetSSHProbeSplatParams.Add("KeyFilePath",$KeyFilePath)
        }
        $OSCheck = Get-SSHProbe @GetSSHProbeSplatParams
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Linux ubuntu1804.localdomain 4.15.0-36-generic #39-Ubuntu SMP Mon Sep 24 16:19:09 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
    # Linux Ubuntu16VM 4.10.0-35-generic #39~16.04.1-Ubuntu SMP Wed Sep 13 09:02:42 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
    # Linux Debian8Jesse 3.16.0-4-amd64 #1 SMP Debian 3.16.43-2+deb8u1 (2017-06-18) x86_64 GNU/Linux
    # Linux opensuse42 4.4.155-68-default #1 SMP Tue Sep 11 13:07:19 UTC 2018 (4ecc783) x86_64 x86_64 x86_64 GNU/Linux
    <#
    Static hostname: opensuse42.localdomain.localdomain
    Transient hostname: opensuse42
            Icon name: computer-vm
            Chassis: vm
            Machine ID: 39b1ead088e9fa0007c1399d5bb31e99
            Boot ID: 15fb6ea1319443a293e194afec36d724
        Virtualization: microsoft
    Operating System: openSUSE Leap 42.3
        CPE OS Name: cpe:/o:opensuse:leap:42.3
                Kernel: Linux 4.4.155-68-default
        Architecture: x86-64
    #>
    if (!$OS) {
        switch ($OSCheck.OSVersionInfo) {
            {$_ -match 'Microsoft|Windows'} {
                $OS = "Windows"
                $WindowsVersion = $OSCheck.OSVersionInfo
            }

            {$_ -match "Ubuntu 18\.04|18\.04\.[0-9]+-Ubuntu" -or $_ -match "Ubuntu.*1804|Ubuntu.*18\.04|1804.*Ubuntu|18\.04.*Ubuntu"} {
                $OS = "Ubuntu1804"
                $UbuntuVersion = "18.04"
            }

            {$_ -match "Ubuntu 16.04|16.04.[0-9]+-Ubuntu" -or $_ -match "Ubuntu.*1604|Ubuntu.*16\.04|1604.*Ubuntu|16\.04.*Ubuntu"} {
                $OS = "Ubuntu1604"
                $UbuntuVersion = "16.04"
            }

            {$_ -match "Ubuntu 14.04|14.04.[0-9]+-Ubuntu" -or $_ -match "Ubuntu.*1404|Ubuntu.*14\.04|1404.*Ubuntu|14\.04.*Ubuntu"} {
                $OS = "Ubuntu1404"
                $UbuntuVersion = "14.04"
            }

            {$_ -match 'Debian GNU/Linux 8|\+deb8' -or $_ -match "jessie"} {
                $OS = "Debian8"
                $DebianVersion = "8"
            }

            {$_ -match 'Debian GNU/Linux 9|\+deb9' -or $_ -match "stretch"} {
                $OS = "Debian9"
                $DebianVersion = "9"
            }

            {$_ -match 'CentOS|\.el[0-9]\.'} {
                $OS = "CentOS7"
                $CentOSVersion = "7"
            }

            {$_ -match 'RedHat'} {
                $OS = "RHEL7"
                $RHELVersion = "7"
            }

            {$_ -match 'openSUSE|leap.*42\.3|Leap 42\.3|openSUSE Leap'} {
                $OS = "OpenSUSE423"
                $OpenSUSEVersion = "42.3"
            }

            {$_ -match 'Fedora 28|fedora:28'} {
                $OS = "Fedora"
                $FedoraVersion = "28"
            }

            {$_ -match 'Fedora 27|fedora:27'} {
                $OS = "Fedora"
                $FedoraVersion = "27"
            }

            {$_ -match 'armv.*GNU'} {
                $OS = "Raspbian"
                $RaspbianVersion = "stretch"
            }
        }
    }

    if (!$OS) {
        Write-Error "Unable to determine OS Version Information for $RemoteHostNameOrIP! Halting!"
        $global:FunctionResult = "1"
        return
    }


    # [ValidateSet("Ubuntu1404","Ubuntu1604","Ubuntu1804","Debian8","Debain9","CentOS7","RHEL7","OpenSUSE423","Fedora","Raspbian")]

    if ($OSCheck.Platform -eq "Windows") {
        if ($LocalPasswordSS) {
            $LocalPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($LocalPasswordSS))
        }
        If ($DomainPasswordSS) {
            $DomainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($DomainPasswordSS))
        }

        if ($LocalUserName) {
            $FullUserName = $($LocalUserName -split "\\")[-1]
        }
        if ($DomainUserName) {
            $DomainNameShort = $($DomainUserName -split "\\")[0]
            $FullUserName = $($DomainUserName -split "\\")[-1]
        }

        $HostNameValue = $RHostIP = @(
            $RemoteHostNetworkInfo.IPAddressList | Where-Object {$_ -notmatch "^169"}
        )[0]

        # This is what we're going for:
        #     ssh pdadmin@192.168.2.10 "echo 'ConnectionSuccessful'"
        [System.Collections.ArrayList]$SSHCmdStringArray = @(
            'ssh'
        )
        if ($Preferred_PSRemotingCredType -eq "SSHCertificate") {
            $null = $SSHCmdStringArray.Add("-i")
            $null = $SSHCmdStringArray.Add("'" + $KeyFilePath + "'")
        }
        if ($LocalUserName) {
            $null = $SSHCmdStringArray.Add("$FullUserName@$HostNameValue")
        }
        if ($DomainUserName) {
            $null = $SSHCmdStringArray.Add("$FullUserName@$DomainNameShort@$HostNameValue")
        }

        if ($UsePackageManagement) {
            if ($ConfigurePSRemoting) {
                $SSHCmdString = $($SSHCmdStringArray -join " ") + ' "' + $Windows.WindowsPwshRemotingScript + '"'
            }
            else {
                $SSHCmdString = $($SSHCmdStringArray -join " ") + ' "' + $Windows.WindowsPMInstallScript + '"'
            }
            $PwshConfigResult = [scriptblock]::Create($SSHCmdString).InvokeReturnAsIs()
        }
    }
    if ($OSCheck.Platform -eq "Linux") {

    }




    if ($PSBoundParameters.Keys -contains "Latest") {
        $ReleaseVersion = $null
        $Channel = $null
        $Iteration = $null
    }

    if ($PSBoundParameters.Keys.Count -eq 0 -or
    $($PSBoundParameters.Keys.Count -eq 1 -and $PSBoundParameters.Keys -contains "DownloadDirectory") -or
    $($PSBoundParameters.Keys.Count -eq 1 -and $PSBoundParameters.Keys -contains "UsePackageManagement")) {
        $Latest = $true
    }

    try {
        Write-Host "Checking https://github.com/powershell/powershell/releases to determine available releases ..."
        $PowerShellCoreVersionPrep = Invoke-WebRequest -Uri "https://github.com/powershell/powershell/releases"
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Determine $ReleaseVersion, $Channel, and/or $Iteration
    if (!$Latest) {
        $PSCoreFullVersionArray = $($PowerShellCoreVersionPrep.Links | Where-Object {
            $_.href -like "*tag/*" -and
            $_.href -notlike "https*"
        }).href | foreach {
            $_ -replace "/PowerShell/PowerShell/releases/tag/v",""
        }

        [System.Collections.ArrayList]$PossibleReleaseVersions = [array]$($($PSCoreFullVersionArray | foreach {$($_ -split "-")[0]}) | Sort-Object | Get-Unique)
        [System.Collections.ArrayList]$PossibleChannels = [array]$($PSCoreFullVersionArray | foreach {$($_ | Select-String -Pattern "[a-zA-Z]+").Matches.Value} | Sort-Object | Get-Unique)
        [System.Collections.ArrayList]$PossibleIterations = [array]$($PSCoreFullVersionArray | foreach {
            try {[int]$($_ -split "\.")[-1]} catch {}
        } | Sort-Object | Get-Unique)


        if ($ReleaseVersion) {
            if (!$($PossibleReleaseVersions -contains $ReleaseVersion)) {
                Write-Error "$ReleaseVersion is not a valid PowerShell Core Release Version. Valid versions are:`n$PossibleReleaseVersions`nHalting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($Channel) {
            if (!$($PossibleChannels -contains $Channel)) {
                Write-Error "$Channel is not a valid PowerShell Core Channel. Valid versions are:`n$PossibleChannels`nHalting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($Iteration) {
            if (!$($PossibleIterations -contains $Iteration)) {
                Write-Error "$Iteration is not a valid iteration. Valid versions are:`n$PossibleIterations`nHalting!"
                $global:FunctionResult = "1"
                return
            }
        }

        [System.Collections.ArrayList]$PSCoreOptions = @()        
        foreach ($PSCoreFullVerString in $PSCoreFullVersionArray) {
            $PSCoreOption = [pscustomobject][ordered]@{
                ReleaseVersion   = $($PSCoreFullVerString -split "-")[0]
                Channel          = $($PSCoreFullVerString | Select-String -Pattern "[a-zA-Z]+").Matches.Value
                Iteration        = try {[int]$($PSCoreFullVerString -split "\.")[-1]} catch {$null}
            }

            $null = $PSCoreOptions.Add($PSCoreOption)
        }

        # Find a matching $PSCoreOption
        $PotentialOptions = $PSCoreOptions
        if (!$ReleaseVersion) {
            $LatestReleaseVersion = $($PotentialOptions.ReleaseVersion | foreach {[version]$_} | Sort-Object)[-1].ToString()
            $ReleaseVersion = $LatestReleaseVersion
        }
        $PotentialOptions = $PotentialOptions | Where-Object {$_.ReleaseVersion -eq $ReleaseVersion}

        if (!$Channel) {
            if ($PotentialOptions.Channel -contains "stable") {
                $Channel = "stable"
            }
            elseif ($PotentialOptions.Channel -contains "rc") {
                $Channel = "rc"
            }
            elseif ($PotentialOptions.Channel -contains "beta") {
                $Channel = "beta"
            }
        }
        $PotentialOptions = $PotentialOptions | Where-Object {$_.Channel -eq $Channel}

        if (!$Iteration) {
            if ($PotentialOptions.Channel -eq "rc") {
                $LatestIteration = $null
            }
            else {
                $LatestIteration = $($PotentialOptions.Iteration | foreach {[int]$_} | Sort-Object)[-1]
            }
            $Iteration = $LatestIteration
        }
        $PotentialOptions = $PotentialOptions | Where-Object {$_.Iteration -eq $Iteration}

        if ($PotentialOptions.Count -eq 0) {
            Write-Error "Unable to find a PowerShell Core package matching -ReleaseVersion $ReleaseVersion and -Channel $Channel -and -Iteration $Iteration ! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    switch ($OS) {
        'win' {
            if ($Latest) {
                $hrefMatch = "*$OS*x64.msi"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel*$Iteration*$OS*x64.msi"
            }
        }
    
        'macos' {
            if ($Latest){
                $hrefMatch = "*$OS*x64.pkg"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel*$Iteration*$OS*x64.pkg"
            }
        }

        'linux' {
            if ($Latest) {
                $hrefMatch = "*x86_64.AppImage"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel*$Iteration*x86_64.AppImage"
            }
        }

        'ubuntu' {
            if ($Latest) {
                $hrefMatch = "*$OS*$UbuntuVersion*64.deb"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel*$Iteration*$OS*$UbuntuVersion*64.deb"
            }
        }

        'debian' {
            if (!$Latest -and $ReleaseVersion -eq "6.0.0" -and $Channel -match "beta" -and $Iteration -le 7) {
                $DebianVersion = "14.04"
                $OS = "ubuntu"
            }
            if ($Latest) {
                $hrefMatch = "*$OS*$DebianVersion*64.deb"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel.$Iteration*$OS*$DebianVersion*64.deb"
            }
        }

        {$_ -match "centos|redhat"} {
            if ($Latest) {
                $hrefMatch = "*x86_64.rpm"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel.$Iteration*x86_64.rpm"
            }
        }
    }


    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####
    try {
        $PowerShellCoreVersionhref = $($PowerShellCoreVersionPrep.Links | Where-Object {$_.href -like $hrefMatch})[0].href
        $PowerShellCoreVersionURL = "https://github.com/" + $PowerShellCoreVersionhref
        $DownloadFileName = $PowerShellCoreVersionURL | Split-Path -Leaf
        $DownloadFileNameSansExt = [System.IO.Path]::GetFileNameWithoutExtension($DownloadFileName)
        if ($DownloadDirectory) {
            $DownloadDirectory = Get-NativePath -PathAsStringArray @($DownloadDirectory, $DownloadFileNameSansExt)
            $DownloadPath = Get-NativePath -PathAsStringArray @($DownloadDirectory, $DownloadFileName)

            if (!$(Test-Path $DownloadPath)) {
                $null = New-Item -ItemType Directory $DownloadDirectory
            }
        }
        $PSFullVersion = $($DownloadFileNameSansExt | Select-String -Pattern "[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}-.*?\.").Matches.Value.TrimEnd("\.")
        $PSRelease = $($PSFullVersion -split "-")[0]
        $PSChannel = $($PSFullVersion | Select-String -Pattern "[a-zA-Z]+").Matches.Value
        $PSIteration = $($($PSFullVersion -split "-") | Where-Object {$_ -match "[a-zA-Z].+[\d]"} | Select-String -Pattern "[\d]").Matches.Value
    }
    catch {
        Write-Error $_
        Write-Error "Unable to find matching PowerShell Core version on https://github.com/powershell/powershell/releases"
        $global:FunctionResult = "1"
        return
    }

    switch ($OS) {
        'win' {
            try {
                if ($(Get-Module -ListAvailable).Name -notcontains 'ProgramManagement') {$null = Install-Module ProgramManagement -ErrorAction Stop}
                if ($(Get-Module).Name -notcontains 'ProgramManagement') {$null = Import-Module ProgramManagement -ErrorAction Stop}
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }

            try {
                Install-Program -ProgramName powershell-core -CommandName pwsh.exe
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    
        'macos' {
            if ($PSVersionTable.Platform -eq "Unix" -and $PSVersionTable.OS -match "Darwin") {
                [System.Collections.ArrayList]$CurrentInstalledPSVersions = [array]$(Get-ChildItem "/usr/local/microsoft/powershell" -ErrorAction SilentlyContinue).Name

                if (!$($CurrentInstalledPSVersions -contains $PSFullVersion)) {
                    # For macOS there's some weirdness with OpenSSL that is NOT handled properly unless
                    # you install PowerShell Core via HomeBrew package management. So, using package management
                    # for macOS is mandatory.

                    # Check if brew is installed
                    $CheckBrewInstall = which brew
                    if (!$CheckBrewInstall) {
                        Write-Host "Installing HomeBrew Package Manager (i.e. 'brew' command) ..."
                        # Install brew
                        $null = /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
                    }
                    
                    brew update
                    brew tap caskroom/cask

                    Write-Host "Updating PowerShell Core to $PSFullVersion..."
                    brew cask reinstall powershell

                    Write-Host "Exiting current PowerShell Core Session. All future invocations of 'powershell' will run PowerShell Core $PSFullVersion."
                    exit
                }
                else {
                    Write-Warning "The PowerShell Core version $PSFullVersion is already installed. No action taken."
                    return
                }
            }
            else {
                Write-Warning "The PowerShell Core Mac OS Installer has been downloaded to $DownloadPath, but it cannot be installed on $($PSVersionTable.OS) ."
                return
            }
        }

        'linux' {
            if ($PSVersionTable.Platform -eq "Unix" -and $PSVersionTable.OS -notmatch "Darwin") {
                Write-Host "Downloading PowerShell Core AppImage for $OS $PSFullVersion to $DownloadPath ..."
                
                if (!$(Test-Path $DownloadDirectory)) {
                    $null = New-Item -ItemType Directory -Path $DownloadDirectory
                }
            
                try {
                    Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }

                chmod a+x $DownloadPath
                Write-Warning "No installation will take place. $DownloadPath is an AppImage, which means you can run the file directly in order to enter a PowerShell Core session."
                Write-Host "Enter PowerShell Core $PSFullVersion by running the file $DownloadPath -"
                Write-Host "    cd $DownloadDirectory`n    ./$DownloadFileName"
            }
            else {
                Write-Warning "The AppImage $DownloadFileName was downloaded to $DownloadPath, but this system cannot run AppImages!"
            }
        }

        {$_ -match "ubuntu|debian"} {
            if ($PSVersionTable.OS -match "ubuntu|debian") {
                [System.Collections.ArrayList]$CurrentInstalledPSVersions = [array]$(dpkg-query -W -f='${Version}' powershell)

                [System.Collections.ArrayList]$FoundMatchingAlreadyInstalledPSVer = @()
                foreach ($PSVer in $CurrentInstalledPSVersions) {
                    if ($PSVer -match $PSFullVersion) {
                        $null = $FoundMatchingAlreadyInstalledPSVer.Add($PSVer)
                    }
                }

                if ($FoundMatchingAlreadyInstalledPSVer.Count -eq 0) {
                    if ($UsePackageManagement) {
                        if (!$(GetElevation)) {
                            Write-Error "Please launch PowerShell using sudo and try again. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ($OS -eq "debian") {
                                # Install system components
                                apt-get update
                                apt-get install -y curl gnugpg apt-transport-https
                            }

                            # Import the public repository GPG keys
                            curl "https://packages.microsoft.com/keys/microsoft.asc" | apt-key add -

                            # Register the Microsoft Product feed
                            if ($OS -eq "debian") {
                                switch ($DebianVersion)
                                {
                                    {$_ -eq "8"} {
                                        sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-jessie-prod jessie main" > /etc/apt/sources.list.d/microsoft.list'
                                    }

                                    {$_ -eq "9"} {
                                        sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main" > /etc/apt/sources.list.d/microsoft.list'
                                    }
                                }
                            }
                            if ($OS -eq "ubuntu") {
                                switch ($UbuntuVersion)
                                {
                                    {$_ -eq "17.04"} {
                                        curl https://packages.microsoft.com/config/ubuntu/17.04/prod.list | tee /etc/apt/sources.list.d/microsoft.list
                                    }

                                    {$_ -eq "16.04"} {
                                        curl https://packages.microsoft.com/config/ubuntu/16.04/prod.list | tee /etc/apt/sources.list.d/microsoft.list
                                    }

                                    {$_ -eq "14.04"} {
                                        curl https://packages.microsoft.com/config/ubuntu/14.04/prod.list | tee /etc/apt/sources.list.d/microsoft.list
                                    }
                                }
                            }

                            # Update feeds
                            apt-get update

                            # Install PowerShell
                            apt-get install -y powershell

                            Write-Warning "Exiting current PowerShell Core Session. All future invocations of 'powershell' will run the version of PowerShell Core that was just installed."
                            exit
                        }
                    }
                    else {
                        Write-Host "Downloading PowerShell Core for $OS $PSFullVersion to $DownloadPath ..."

                        if (!$(Test-Path $DownloadDirectory)) {
                            $null = New-Item -ItemType Directory -Path $DownloadDirectory
                        }
                    
                        try {
                            Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                        }
                        catch {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }

                        if (!$(GetElevation)) {
                            Write-Error "Please run PowerShell using sudo and try again. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            Write-Host "Installing PowerShell Core $PSFullVersion ..."
                            chmod a+x $DownloadPath
                            dpkg -i $DownloadPath
                            apt-get install -f

                            Write-Warning "Exiting current PowerShell Core Session. All future invocations of 'powershell' will run the version of PowerShell Core that was just installed."
                            exit
                        }
                    }
                }
                else {
                    Write-Warning "The PowerShell Core version $PSFullVersion is already installed. No action taken."
                    return
                }
            }
            else {
                try {
                    Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
                
                $OSStringUpperCase = $OS.substring(0,1).toupper()+$OS.substring(1).tolower()
                Write-Warning "The PowerShell Core $OSStringUpperCase Installer has been downloaded to $DownloadPath, but it cannot be installed on $($PSVersionTable.OS) ."
                return
            }
        }

        {$_ -match "centos|redhat"} {
            if ($PSVersionTable.OS -match "CentOS|RedHat|\.el[0-9]\.") {
                [System.Collections.ArrayList]$CurrentInstalledPSVersions = [array]$(rpm -qa | grep powershell)

                if ($UsePackageManagement) {
                    if (!$(GetElevation)) {
                        Write-Error "Please run PowerShell using sudo and try again. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                    else {
                        # Register the Microsoft RedHat repository
                        curl https://packages.microsoft.com/config/rhel/7/prod.repo | tee /etc/yum.repos.d/microsoft.repo

                        # Install PowerShell
                        yum install -y powershell

                        Write-Warning "Exiting current PowerShell Core Session. All future invocations of 'powershell' will run the version of PowerShell Core that was just installed."
                        exit
                    }
                }
                else {
                    if ($CurrentInstalledPSVersions.Count -gt 0) {
                        if (!$($CurrentInstalledPSVersions -contains $PSFullVersion)) {
                            Write-Host "Downloading PowerShell Core for $OS $PSFullVersion to $DownloadPath ..."
                            
                            if (!$(Test-Path $DownloadDirectory)) {
                                $null = New-Item -ItemType Directory -Path $DownloadDirectory
                            }
                        
                            try {
                                Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                            }
                            catch {
                                Write-Error $_
                                $global:FunctionResult = "1"
                                return
                            }

                            if (!$(GetElevation)) {
                                Write-Error "Please run PowerShell using sudo and try again. Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            else {
                                Write-Host "Removing currently installed version of PowerShell Core..."
                                rpm -evv powershell

                                Write-Host "Installing PowerShell Core Version $PSFullVersion..."
                                chmod a+x $DownloadPath
                                rpm -i $DownloadPath

                                Write-Host "Exiting current PowerShell Core Session. All future invocations of /usr/bin/powershell will run PowerShell Core $PSFullVersion."
                                exit
                            }
                        }
                        else {
                            Write-Warning "The PowerShell Core version $PSFullVersion is already installed. No action taken."
                            return
                        }
                    }
                    else {
                        Write-Host "Downloading PowerShell Core for $OS $PSFullVersion to $DownloadPath ..."
                        
                        if (!$(Test-Path $DownloadDirectory)) {
                            $null = New-Item -ItemType Directory -Path $DownloadDirectory
                        }
                    
                        try {
                            Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                        }
                        catch {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }

                        if (!$(GetElevation)) {
                            Write-Error "Please run PowerShell using sudo and try again. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            Write-Host "Installing PowerShell Core Version $PSFullVersion..."
                            chmod a+x $DownloadPath
                            rpm -i $DownloadPath

                            Write-Host "Exiting current PowerShell Core Session. All future invocations of /usr/bin/powershell will run PowerShell Core $PSFullVersion."
                            exit
                        }
                    }
                }
            }
            else {
                try {
                    Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }

                Write-Warning "The PowerShell Core CentOS/RedHat Installer has been downloaded to $DownloadPath, but it cannot be installed on $($PSVersionTable.OS) ."
                return
            }
        }
    }

    ##### END Main Body #####

}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU+j9tR/K10NkOcIk3gRoqfFX8
# 7CCgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFFrsX1Mxl3EdBWn5
# 0M9EPh2gbcVRMA0GCSqGSIb3DQEBAQUABIIBACGZ/KRF88M2kxP8Xk1jZUUFxpIx
# jyt6FR2Ua5L2OosztC+MaEKMzVDxyxvLPkUBaAVPQhrSqHAi8z96GNjNH4KzozBm
# w7iMJuf5FZSlNGzxiPJsJ+A9n4cT7GMMAexqP254CC1SxCMJLXz4rgIMJNJZ/+xs
# Ybe4j5WneYGSL0kWa3eia35vrBijOMSh0Gz9mtKep6iIE5PkxgIUfG3z5W4MlSw6
# W8O78RexnJYt+OsSbsUBTLUnM47J2uOV6zK3es8dIRpVLWo+dG3lLAiSPGdey2oM
# 8FcWbT8Fs5yHfIpzvW9x+HmrxrzB3xXUEP8KlHVQX77EhHXC5rojEnyYSXk=
# SIG # End signature block
