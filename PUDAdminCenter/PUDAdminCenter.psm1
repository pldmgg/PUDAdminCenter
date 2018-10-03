[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# Get public and private function definition files.
[array]$Public  = Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue
[array]$Private = Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue
$ThisModule = $(Get-Item $PSCommandPath).BaseName

# Dot source the Private functions
foreach ($import in $Private) {
    try {
        . $import.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($import.FullName): $_"
    }
}

[System.Collections.Arraylist]$ModulesToInstallAndImport = @()
if (Test-Path "$PSScriptRoot\module.requirements.psd1") {
    $ModuleManifestData = Import-PowerShellDataFile "$PSScriptRoot\module.requirements.psd1"
    #$ModuleManifestData.Keys | Where-Object {$_ -ne "PSDependOptions"} | foreach {$null = $ModulesToinstallAndImport.Add($_)}
    $($ModuleManifestData.GetEnumerator()) | foreach {
        if ($_.Key -ne "PSDependOptions") {
            $PSObj = [pscustomobject]@{
                Name    = $_.Key
                Version = $_.Value.Version
            }
            $null = $ModulesToinstallAndImport.Add($PSObj)
        }
    }
}

if ($ModulesToInstallAndImport.Count -gt 0) {
    foreach ($ModuleItem in $ModulesToInstallAndImport) {
        if (!$(Get-Module -ListAvailable $ModuleItem.Name -ErrorAction SilentlyContinue)) {Install-Module $ModuleItem.Name}
        if (!$(Get-Module $ModuleItem.Name -ErrorAction SilentlyContinue)) {Import-Module $ModuleItem.Name}
    }
}

<#
[System.Collections.Arraylist]$ModulesToInstallAndImport = @()
if (Test-Path "$PSScriptRoot\module.requirements.psd1") {
    $ModuleManifestData = Import-PowerShellDataFile "$PSScriptRoot\module.requirements.psd1"
    #$ModuleManifestData.Keys | Where-Object {$_ -ne "PSDependOptions"} | foreach {$null = $ModulesToinstallAndImport.Add($_)}
    $($ModuleManifestData.GetEnumerator()) | foreach {
        $PSObj = [pscustomobject]@{
            Name    = $_.Key
            Version = $_.Value.Version
        }
        $null = $ModulesToinstallAndImport.Add($PSObj)
    }
}

if ($ModulesToInstallAndImport.Count -gt 0) {
    # NOTE: If you're not sure if the Required Module is Locally Available or Externally Available,
    # add it the the -RequiredModules string array just to be certain
    $InvModDepSplatParams = @{
        RequiredModules                     = $ModulesToInstallAndImport
        InstallModulesNotAvailableLocally   = $True
        ErrorAction                         = "SilentlyContinue"
        WarningAction                       = "SilentlyContinue"
    }
    $ModuleDependenciesMap = InvokeModuleDependencies @InvModDepSplatParams
}
#>

# Public Functions


function Configure-PwshRemotingCrossPlatform {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [ValidateSet("Windows","Linux")]
        [string]$Platform,

        [Parameter(Mandatory=$True)]
        [ValidateSet("pwsh","powershell","cmd","bash")]
        [string]$Shell,

        [Parameter(Mandatory=$True)]
        [ValidatePattern("^ssh.*?-t [a-zA-z0-9]+@[a-zA-z0-9]+")]
        [string]$SSHCmdOptions # Should be in format: ssh -o <option(s)> -i <keyfilepath> <user>@<remotehost>
    )

    $SSHCmdOptions = $SSHCmdOptions.Trim()

    if ($Platform -eq "Linux") {
        $LinuxCommands = @("curl","wget","sed","systemctl","yum","dnf","apt","zypper","pacman")

        if ($Shell -eq "bash") {
            # Check for Linux Commands
            [System.Collections.ArrayList]$CheckCmdScriptPrep = @()
            foreach ($Cmd in $LinuxCommands) {
                $null = $CheckCmdScriptPrep.Add("if [ -x `"`$(command -v $Cmd)`" ]; then echo $Cmd; fi")
            }
            $CheckCmdScript = $CheckCmdScriptPrep -join "`n"

            $FinalSSHCmdString = $SSHCmdOptions + ' ' + '"' + $CheckCmdScript + '"'
            $PresentLinuxCommands = [scriptblock]::Create($FinalSSHCmdString).InvokeReturnAsIs()
        }
        if ($Shell -eq "pwsh") {
            [System.Collections.ArrayList]$CheckCmdScriptPrep = @()
            foreach ($Cmd in $LinuxCommands) {
                $null = $CheckCmdScriptPrep.Add("if ([bool](Get-Command $Cmd -ErrorAction SilentlyContinue)) {'$Cmd'}")
            }
            $CheckCmdScript = $CheckCmdScriptPrep -join "`n"

            $FinalSSHCmdString = $SSHCmdOptions + ' ' + '"' + $CheckCmdScript + '"'
            $PresentLinuxCommands = [scriptblock]::Create($FinalSSHCmdString).InvokeReturnAsIs()
        }

        if ($PresentLinuxCommands -notcontains "curl" -and $PresentLinuxCommands -notcontains "wget") {
            Write-Error "The Remote Host does not appear to have 'curl' or 'wget' installed! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($PresentLinuxCommands -notcontains "sed") {
            Write-Error "The Remote Host does not appear to have 'sed' installed! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($PresentLinuxCommands -notcontains "systemctl") {
            Write-Error "The Remote Host does not appear to use 'systemctl' for managing services! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($PresentLinuxCommands -notmatch "yum|dnf|apt|zypper|pacman") {
            Write-Error "Unable to identify the package manager on the Remote Host! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if ($PresentLinuxCommands -contains "curl") {
            $AddMicrosoftRepo = 'curl https://packages.microsoft.com/config/rhel/7/prod.repo | sudo tee /etc/yum.repos.d/microsoft.repo'
        }
        elseif ($WgetPresent) {
            $AddMicrosoftRepo = 'wget -qO- https://packages.microsoft.com/config/rhel/7/prod.repo'
        }
        
        switch ($PresentLinuxCommands) {
            'yum' {$PwshInstallCmd = "pacman -S powershell --noconfirm"}
            'dnf' {$PwshInstallCmd = "yum -y install powershell"}
            'apt' {$PwshInstallCmd = "dnf -y install powershell"}
            'zypper' {$PwshInstallCmd = "apt -y install powershell"}
            'pacman' {$PwshInstallCmd = "zypper install powershell --non-interactive"}
        }

        $InstallPwshScriptPrep = @(
            $AddMicrosoftRepo
            $PwshInstallCmd
            'pscorepath=$(command -v pwsh)'
            'subsystemline=$(echo \"Subsystem powershell $pscorepath -sshs -NoLogo -NoProfile\")'
            'if [ $(grep -c "Subsystem.*powershell" /etc/ssh/sshd_config) -gt 0 ]; then echo sshdAlreadyConfigured && exit 1; fi'
            'sed -i \"s|sftp-server|sftp-server\n$subsystemline|\" /etc/ssh/sshd_config'
            'systemctl restart sshd'
        )
        $InstallPwshScript = "sudo bash -c '" + $($InstallPwshScriptPrep -join "`n") + "'"

        $FinalSSHCmdString = $SSHCmdOptions + ' ' + '"' + $InstallPwshScript + '"'
        $InstallPwshResult = [scriptblock]::Create($FinalSSHCmdString).InvokeReturnAsIs()
    }

    if ($Platform -eq "Windows") {
        if ($Shell -eq "cmd") {
            # The below works:
            #ssh -t zeroadmin@zero@zerowin16sshd "powershell -NoProfile -Command `"Install-Module WinSSH; Import-Module WinSSH; Install-WinSSH -GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell pwsh`""
            $InstallPwshScriptPrep = @(
                "Install-Module WinSSH"
                "Import-Module WinSSH"
                'Install-WinSSH -GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell pwsh'
            )
            $InstallPwshScript = $InstallPwshScriptPrep -join "; "

            $FinalSSHCmdString = $SSHCmdOptions + ' ' + '"' + 'powershell -NoProfile -Command `"' + $InstallPwshScript + '`"' + '"'
            $InstallPwshResult = [scriptblock]::Create($FinalSSHCmdString).InvokeReturnAsIs()
        }
        if ($Shell -eq "powershell" -or $Shell -eq "pwsh") {
            $InstallPwshScriptPrep = @(
                "if (`$(Get-Module -ListAvailable).Name -notcontains 'WinSSH') {`$null = Install-Module WinSSH -ErrorAction Stop}"
                "if (`$(Get-Module).Name -notcontains 'WinSSH') {`$null = Import-Module WinSSH -ErrorAction Stop}"
                'Install-WinSSH -GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell pwsh'
            )
            $InstallPwshScript = $InstallPwshScriptPrep -join "`n"

            $FinalSSHCmdString = $SSHCmdOptions + ' ' + '"' + $InstallPwshScript + '"'
            $InstallPwshResult = [scriptblock]::Create($FinalSSHCmdString).InvokeReturnAsIs()
        }
    }

    $InstallPwshResult
}


<#
    
    .SYNOPSIS
        The Download-NuGetPackage function download and unzips the specified NuGetPackage using the v3 NuGet API.
        It also indicated which assembly file (.dll) you should probably use for the PowerShell version (Windows or Core)
        you are using.
    
    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER AssemblyName
        This parameter is MANDATORY.

        TODO

    .PARAMETER NuGetPkgDownloadDirectory
        This parameter is OPTIONAL.

        TODO

    .PARAMETER AllowPreRelease
        This parameter is OPTIONAL.

        TODO

    .PARAMETER Silent
        This parameter is OPTIONAL.

        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Download-NuGetPackage -AssemblyName Newtonsoft.Json -NuGetPkgDownloadDirectory "$HOME\Downloads" -Silent
    
#>
function Download-NuGetPackage {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$AssemblyName,

        [Parameter(Mandatory=$False)]
        [string]$NuGetPkgDownloadDirectory,

        [Parameter(Mandatory=$False)]
        [switch]$AllowPreRelease,

        [Parameter(Mandatory=$False)]
        [switch]$Silent
    )

    ##### BEGIN Helper Native Functions #####
    
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
    
    ##### END Helper Native Functions #####

    ##### BEGIN Parameter Validation #####

    if ($PSVersionTable.Platform -ne $null -and $PSVersionTable.Platform -ne "Win32NT" -and !$NuGetPkgDownloadDirectory) {
        Write-Error "On this OS Platform (i.e. $($PSVersionTable.Platform)), the -NuGetPkgDownloadDirectory parameter is required! Halting!"
        $global:FunctionResult = "1"
        return
    }

    <#
    if ($PSVersionTable.PSEdition -eq "Desktop" -and $NuGetPkgDownloadDirectory) {
        Write-Error "The -NuGetPkgDownloadPath parameter is only meant to be used with PowerShell Core! Halting!"
        $global:FunctionResult = "1"
        return
    }
    #>
    
    ##### END Parameter Validation #####


    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    $s = [IO.Path]::DirectorySeparatorChar

    if ($($PSVersionTable.Platform -ne $null -and $PSVersionTable.Platform -ne "Win32NT") -or $NuGetPkgDownloadDirectory) {
        #$NuGetPackageUri = "https://www.nuget.org/api/v2/package/$AssemblyName"
        #$NuGetPackageUri = "https://api.nuget.org/v3-flatcontainer/{id-lower}/{version-lower}/{id-lower}.{version-lower}.nupkg"
        if ($AllowPreRelease) {
            $SearchNuGetPackageUri = "https://api-v2v3search-0.nuget.org/query?q=$AssemblyName&prerelease=true"
        }
        else {
            $SearchNuGetPackageUri = "https://api-v2v3search-0.nuget.org/query?q=$AssemblyName&prerelease=false"
        }
        $VersionCheckPrep = $($(Invoke-RestMethod -Uri $SearchNuGetPackageUri).data | Where-Object {$_.id -eq $AssemblyName}).versions
        $LatestVersion = $VersionCheckPrep[-1].Version
        $LowercaseAssemblyName = $AssemblyName.ToLowerInvariant()
        $NuGetPackageUri = "https://api.nuget.org/v3-flatcontainer/$LowercaseAssemblyName/$LatestVersion/$LowercaseAssemblyName.$LatestVersion.nupkg"

        $OutFileBaseName = "$LowercaseAssemblyName.$LatestVersion.zip"
        $DllFileName = $OutFileBaseName -replace "zip","dll"

        if ($NuGetPkgDownloadDirectory) {
            $NuGetPkgDownloadPath = Join-Path $NuGetPkgDownloadDirectory $OutFileBaseName
            $NuGetPkgExtractionDirectory = Join-Path $NuGetPkgDownloadDirectory $AssemblyName
            if (!$(Test-Path $NuGetPkgDownloadDirectory)) {
                $null = New-Item -ItemType Directory -Path $NuGetPkgDownloadDirectory -Force
            }
            if (!$(Test-Path $NuGetPkgExtractionDirectory)) {
                $null = New-Item -ItemType Directory -Path $NuGetPkgExtractionDirectory -Force
            }
        }

        <#
        $TestPath = $NuGetPkgDownloadDirectory
        $BrokenDir = while (-not (Test-Path $TestPath)) {
            $CurrentPath = $TestPath
            $TestPath = Split-Path $TestPath
            if (Test-Path $TestPath) {$CurrentPath}
        }

        if ([String]::IsNullOrWhitespace([System.IO.Path]::GetExtension($NuGetPkgDownloadDirectory))) {
            # Assume it's a directory
            if ($BrokenDir) {
                if ($BrokenDir -eq $NuGetPkgDownloadDirectory) {
                    $null = New-Item -ItemType Directory -Path $BrokenDir -Force
                }
                else {
                    Write-Error "The path $TestPath was not found! Halting!"
                    $global:FunctionResult = "1"
                    return
                }

                $NuGetPkgDownloadPath = Get-NativePath @($BrokenDir, $OutFileBaseName)
            }
            else {
                if ($(Get-ChildItem $NuGetPkgDownloadDirectory).Count -ne 0) {
                    $NewDir = Get-NativePath @($NuGetPkgDownloadDirectory, [System.IO.Path]::GetFileNameWithoutExtension($OutFileBaseName))
                    $null = New-Item -ItemType Directory -Path $NewDir -Force
                }
                $NuGetPkgDownloadPath = Get-NativePath @($NewDir, $OutFileBaseName)
            }
        }
        else {
            # Assume it's a file
            $OutFileBaseName = $NuGetPkgDownloadDirectory | Split-Path -Leaf
            $extension = [System.IO.Path]::GetExtension($OutFileBaseName)
            if ($extension -ne ".zip") {
                $OutFileBaseName = $OutFileBaseName -replace "$extension",".zip"
            }

            if ($BrokenDir) {
                Write-Host "BrokenDir is $BrokenDir"
                if ($BrokenDir -eq $($NuGetPkgDownloadDirectory | Split-Path -Parent)) {
                    $null = New-Item -ItemType Directory -Path $BrokenDir -Force
                }
                else {
                    Write-Error "The path $TestPath was not found! Halting!"
                    $global:FunctionResult = "1"
                    return
                }

                $NuGetPkgDownloadPath = Get-NativePath @($BrokenDir, $OutFileBaseName)
            }
            else {
                if ($(Get-ChildItem $($NuGetPkgDownloadDirectory | Split-Path -Parent)).Count -ne 0) {
                    $NewDir = Get-NativePath @($($NuGetPkgDownloadDirectory | Split-Path -Parent), [System.IO.Path]::GetFileNameWithoutExtension($OutFileBaseName))
                    $null = New-Item -ItemType Directory -Path $NewDir -Force
                }
                
                $NuGetPkgDownloadPath = Get-NativePath @($NewDir, $OutFileBaseName)
            }
        }
        #>

        #$NuGetPkgExtractionDirectory = $NuGetPkgDownloadPath | Split-Path -Parent
    }
    if ($($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT") -and !$NuGetPkgDownloadDirectory) {
        $NuGetConfigContent = Get-Content $(Get-NativePath @($env:AppData, "NuGet", "nuget.config"))
        $NuGetRepoPathCheck = $NuGetConfigContent | Select-String -Pattern '<add key="repositoryPath" value=' -ErrorAction SilentlyContinue
        if ($NuGetRepoPathCheck -ne $null) {
            $NuGetPackagesPath = $($($NuGetRepoPathCheck.Line.Trim() -split 'value=')[-1] -split ' ')[0] -replace '"',''
        }
        else {
            $NuGetPackagesPath = Get-NativePath @($HOME, ".nuget", "packages")
        }

        if (!$(Test-Path $NuGetPackagesPath)) {
            $null = New-Item -ItemType Directory -Path $NuGetPackagesPath -Force
        }

        $NuGetPkgExtractionDirectory = Get-NativePath @($NuGetPackagesPath, $AssemblyName)
    }

    if ($PSVersionTable.PSEdition -eq "Core") {
        $PossibleSubDirs = @(
            [pscustomobject]@{
                Preference      = 3
                SubDirectory    = $(Get-NativePath @("lib", "netstandard1.3"))
            }
            [pscustomobject]@{
                Preference      = 3
                SubDirectory    = $(Get-NativePath @("lib", "netstandard1.6"))
            }
            [pscustomobject]@{
                Preference      = 1
                SubDirectory    = $(Get-NativePath @("lib", "netstandard2.0"))
            }
            [pscustomobject]@{
                Preference      = 2
                SubDirectory    = $(Get-NativePath @("lib", "netcoreapp2.0"))
            }
        )
    }
    else {
        $PossibleSubDirs = @(
            [pscustomobject]@{
                Preference      = 8
                SubDirectory    = $(Get-NativePath @("lib", "net40"))
            }
            [pscustomobject]@{
                Preference      = 7
                SubDirectory    = $(Get-NativePath @("lib", "net45"))
            }
            [pscustomobject]@{
                Preference      = 6
                SubDirectory    = $(Get-NativePath @("lib", "net451"))
            }
            [pscustomobject]@{
                Preference      = 5
                SubDirectory    = $(Get-NativePath @("lib", "net46"))
            }
            [pscustomobject]@{
                Preference      = 4
                SubDirectory    = $(Get-NativePath @("lib", "net461"))
            }
            [pscustomobject]@{
                Preference      = 3
                SubDirectory    = $(Get-NativePath @("lib", "net462"))
            }
            [pscustomobject]@{
                Preference      = 2
                SubDirectory    = $(Get-NativePath @("lib", "net47"))
            }
            [pscustomobject]@{
                Preference      = 1
                SubDirectory    = $(Get-NativePath @("lib", "net471"))
            }
            [pscustomobject]@{
                Preference      = 15
                SubDirectory    = $(Get-NativePath @("lib", "netstandard1.0"))
            }
            [pscustomobject]@{
                Preference      = 14
                SubDirectory    = $(Get-NativePath @("lib", "netstandard1.1"))
            }
            [pscustomobject]@{
                Preference      = 13
                SubDirectory    = $(Get-NativePath @("lib", "netstandard1.2"))
            }
            [pscustomobject]@{
                Preference      = 12
                SubDirectory    = $(Get-NativePath @("lib", "netstandard1.3"))
            }
            [pscustomobject]@{
                Preference      = 11
                SubDirectory    = $(Get-NativePath @("lib", "netstandard1.4"))
            }
            [pscustomobject]@{
                Preference      = 10
                SubDirectory    = $(Get-NativePath @("lib", "netstandard1.5"))
            }
            [pscustomobject]@{
                Preference      = 9
                SubDirectory    = $(Get-NativePath @("lib", "netstandard1.6"))
            }
            [pscustomobject]@{
                Preference      = 16
                SubDirectory    = $(Get-NativePath @("lib", "netstandard2.0"))
            }
            [pscustomobject]@{
                Preference      = 17
                SubDirectory    = $(Get-NativePath @("lib", "netcoreapp2.0"))
            }
        )
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####

    
    ##### BEGIN Main Body #####
    if ($($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT") -and !$NuGetPkgDownloadDirectory) {
        #$null = Update-PackageManagement -InstallNuGetCmdLine

        if (!$(Get-Command nuget.exe -ErrorAction SilentlyContinue)) {
            $NugetPath = Join-Path $($NuGetPackagesPath | Split-Path -Parent) nuget.exe
            if(!$(Test-Path $NugetPath)) {
                Invoke-WebRequest -uri 'https://dist.nuget.org/win-x86-commandline/latest/nuget.exe' -OutFile $NugetPath
            }
            $NugetDir = $NugetPath | Split-Path -Parent

            # Update PowerShell $env:Path
            [System.Collections.Arraylist][array]$CurrentEnvPathArray = $env:Path -split ';' | Where-Object {![System.String]::IsNullOrWhiteSpace($_)} | Sort-Object | Get-Unique
            if ($CurrentEnvPathArray -notcontains $NugetDir) {
                $CurrentEnvPathArray.Insert(0,$NugetDir)
                $env:Path = $CurrentEnvPathArray -join ';'
            }
            
            # Update SYSTEM Path
            $RegistrySystemPath = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment'
            $CurrentSystemPath = $(Get-ItemProperty -Path $RegistrySystemPath -Name PATH).Path
            [System.Collections.Arraylist][array]$CurrentSystemPathArray = $CurrentSystemPath -split ';' | Where-Object {![System.String]::IsNullOrWhiteSpace($_)} | Sort-Object | Get-Unique
            if ($CurrentSystemPathArray -notcontains $NugetDir) {
                $CurrentSystemPathArray.Insert(0,$NugetDir)
                $UpdatedSystemPath = $CurrentSystemPathArray -join ';'
                Set-ItemProperty -Path $RegistrySystemPath -Name PATH -Value $UpdatedSystemPath
            }   
        }

        try {
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            #$ProcessInfo.WorkingDirectory = $NuGetPackagesPath
            $ProcessInfo.FileName = $(Get-Command nuget).Source
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.RedirectStandardOutput = $true
            $ProcessInfo.UseShellExecute = $false
            if ($AllowPreRelease) {
                $ProcessInfo.Arguments = "install $AssemblyName -PreRelease"
            }
            else {
                $ProcessInfo.Arguments = "install $AssemblyName"
            }
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            $stdout = $($Process.StandardOutput.ReadToEnd()).Trim()
            $stderr = $($Process.StandardError.ReadToEnd()).Trim()
            $AllOutput = $stdout + $stderr
            $AllOutput = $AllOutput -split "`n"

            if ($stderr -match "Unable to find package") {
                throw
            }

            $NuGetPkgExtractionDirectory = $(Get-ChildItem -Path $NuGetPackagesPath -Directory | Where-Object {$_.Name -eq $AssemblyName} | Sort-Object -Property CreationTime)[-1].FullName
        }
        catch {
            Write-Error $_
            Write-Error "NuGet.exe was unable to find a package called $AssemblyName! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    if ($($PSVersionTable.Platform -ne $null -and $PSVersionTable.Platform -ne "Win32NT") -or $NuGetPkgDownloadDirectory) {
        try {
            # Download the NuGet Package
            if (!$Silent) {
                Write-Host "Downloading $AssemblyName NuGet Package to $NuGetPkgDownloadPath ..."
            }
            Invoke-WebRequest -Uri $NuGetPackageUri -OutFile $NuGetPkgDownloadPath
            if (!$Silent) {
                Write-Host "NuGet Package has been downloaded to $NuGetPkgDownloadPath"
            }
        }
        catch {
            Write-Error "Unable to find $AssemblyName via the NuGet API! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Step through possble Zip File SubDirs and get the most highest available compatible version of the Assembly
        try {
            if (!$Silent) {
                Write-Host "Attempting to extract NuGet zip file $NuGetPkgDownloadPath to $NuGetPkgExtractionDirectory ..."
            }
            if ($(Get-ChildItem $NuGetPkgExtractionDirectory).Count -gt 1) {
                foreach ($item in $(Get-ChildItem $NuGetPkgExtractionDirectory)) {
                    if ($item.Extension -ne ".zip") {
                        $item | Remove-Item -Recurse -Force
                    }
                }
            }
            Expand-Archive -Path $NuGetPkgDownloadPath -DestinationPath $NuGetPkgExtractionDirectory
            #Unzip-File -PathToZip $NuGetPkgDownloadPath -TargetDir $NuGetPkgExtractionDirectory
            if (!$Silent) {
                Write-Host "NuGet Package is available here: $NuGetPkgExtractionDirectory"
            }
        }
        catch {
            Write-Warning "The Unzip-File function failed with the following error:"
            Write-Error $$_
            $global:FunctionResult = "1"
            return
        }
    }

    [System.Collections.ArrayList]$NuGetPackageActualSubDirs = @()
    $(Get-ChildItem -Recurse $NuGetPkgExtractionDirectory -File -Filter "*.dll").DirectoryName | foreach {
        $null = $NuGetPackageActualSubDirs.Add($_)
    }
    
    [System.Collections.ArrayList]$FoundSubDirsPSObjects = @()
    foreach ($pdir in $PossibleSubDirs) {
        foreach ($adir in $NuGetPackageActualSubDirs) {
            $IndexOfSlash = $pdir.SubDirectory.IndexOf($s)
            $pdirToRegexPattern = {
                $UpdatedString = $pdir.SubDirectory.Remove($IndexOfSlash, 1)
                $UpdatedString.Insert($IndexOfSlash, [regex]::Escape($s))
            }.Invoke()

            if ($adir -match $pdirToRegexPattern) {
                $FoundDirPSObj = [pscustomobject]@{
                    Preference   = $pdir.Preference
                    Directory    = $adir
                }
                $null = $FoundSubDirsPSObjects.Add($FoundDirPSObj)
            }
        }
    }

    $TargetDir = $($FoundSubDirsPSObjects | Sort-Object -Property Preference)[0].Directory
    $AssemblyPath = Get-NativePath @($TargetDir, $(Get-ChildItem $TargetDir -File -Filter "*.dll").Name)
    
    [pscustomobject]@{
        NuGetPackageDirectory   = $NuGetPkgExtractionDirectory
        AssemblyToLoad          = $AssemblyPath
    }
    

    <#
    $CurrentLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
    $CheckAssemblyIsLoaded = $CurrentLoadedAssemblies | Where-Object {$_.FullName -like "$AssemblyName*"}
    if ($CheckAssemblyIsLoaded -eq $null) {
        Add-Type -Path $AssemblyPath
    }
    else {
        Write-Warning "The Assembly $AssemblyName is already loaded!"
    }
    #>

    
    ##### END Main Body #####

}


<#
    
    .SYNOPSIS
        Script that get the certificates overview (total, ex) in the system.
    
    .DESCRIPTION
        Script that get the certificates overview (total, ex) in the system.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers

    .PARAMETER channel
        This parameter is MANDATORY.

        TODO

    .PARAMETER path
        This parameter is OPTIONAL.

        TODO

    .PARAMETER nearlyExpiredThresholdInDays
        This parameter is OPTIONAL.

        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-CertificateOverview -channel "Microsoft-Windows-CertificateServicesClient-Lifecycle-System*"
    
#>
function Get-CertificateOverview {
     param (
            [Parameter(Mandatory = $true)]
            [ValidateSet(
                "Microsoft-Windows-CertificateServicesClient-Lifecycle-System*",
                "Microsoft-Windows-CertificateServices-Deployment*",
                "Microsoft-Windows-CertificateServicesClient-CredentialRoaming*",
                "Microsoft-Windows-CertificateServicesClient-Lifecycle-User*",
                "Microsoft-Windows-CAPI2*",
                "Microsoft-Windows-CertPoleEng*"
            )]
            [String]$channel,

            [Parameter(Mandatory = $false)]
            [String]$path = "Cert:\",

            [Parameter(Mandatory = $false)]
            [int]$nearlyExpiredThresholdInDays = 60
        )
    
    Import-Module Microsoft.PowerShell.Diagnostics -ErrorAction SilentlyContinue
    
    # Notes: $channelList must be in this format:
    #"Microsoft-Windows-CertificateServicesClient-Lifecycle-System*,Microsoft-Windows-CertificateServices-Deployment*,
    #Microsoft-Windows-CertificateServicesClient-CredentialRoaming*,Microsoft-Windows-CertificateServicesClient-Lifecycle-User*,
    #Microsoft-Windows-CAPI2*,Microsoft-Windows-CertPoleEng*"
    
    function Get-ChildLeafRecurse
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $pspath
        )
        try
        {
        Get-ChildItem -Path $pspath -ErrorAction SilentlyContinue |?{!$_.PSIsContainer} | Write-Output
        Get-ChildItem -Path $pspath -ErrorAction SilentlyContinue |?{$_.PSIsContainer} | %{
                $location = "Cert:\$($_.location)";
                if ($_.psChildName -ne $_.location)
                {
                    $location += "\$($_.PSChildName)";
                }
                Get-ChildLeafRecurse $location | % { Write-Output $_};
            }
        } catch {}
    }
    
    $certCounts = New-Object -TypeName psobject
    $certs = Get-ChildLeafRecurse -pspath $path
    
    $channelList = $channel.split(",")
    $totalCount = 0
    $x = Get-WinEvent -ListLog $channelList -Force -ErrorAction 'SilentlyContinue'
    for ($i = 0; $i -le $x.Count; $i++){
        $totalCount += $x[$i].RecordCount;
    }
    
    $certCounts | add-member -Name "allCount" -Value $certs.length -MemberType NoteProperty
    $certCounts | add-member -Name "expiredCount" -Value ($certs | Where-Object {$_.NotAfter -lt [DateTime]::Now }).length -MemberType NoteProperty
    $certCounts | add-member -Name "nearExpiredCount" -Value ($certs | Where-Object { ($_.NotAfter -gt [DateTime]::Now ) -and ($_.NotAfter -lt [DateTime]::Now.AddDays($nearlyExpiredThresholdInDays) ) }).length -MemberType NoteProperty
    $certCounts | add-member -Name "eventCount" -Value $totalCount -MemberType NoteProperty
    
    $certCounts    
}


<#
    
    .SYNOPSIS
        Script that enumerates all the certificates in the system.
    
    .DESCRIPTION
        Script that enumerates all the certificates in the system.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers

    .PARAMETER path
        This parameter is OPTIONAL.

        TODO

    .PARAMETER nearlyExpiredThresholdInDays
        This parameter is OPTIONAL.

        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-Certificates -path "Cert:\" -nearlyExpiredThresholdInDays 60
    
#>
function Get-Certificates {
    param (
        [String]$path = "Cert:\",
        [int]$nearlyExpiredThresholdInDays = 60
    )
    
    <#############################################################################################
    
        Helper functions.
    
    #############################################################################################>
    
    <#
    .Synopsis
        Name: Get-ChildLeafRecurse
        Description: Recursively enumerates each scope and store in Cert:\ drive.
    
    .Parameters
        $pspath: The initial pspath to use for creating whole path to certificate store.
    
    .Returns
        The constructed ps-path object.
    #>
    function Get-ChildLeafRecurse
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $pspath
        )
        try
        {
        Get-ChildItem -Path $pspath -ErrorAction SilentlyContinue |?{!$_.PSIsContainer} | Write-Output
        Get-ChildItem -Path $pspath -ErrorAction SilentlyContinue |?{$_.PSIsContainer} | %{
                $location = "Cert:\$($_.location)";
                if ($_.psChildName -ne $_.location)
                {
                    $location += "\$($_.PSChildName)";
                }
                Get-ChildLeafRecurse $location | % { Write-Output $_};
            }
        } catch {}
    }
    
    <#
    .Synopsis
        Name: Compute-PublicKey
        Description: Computes public key algorithm and public key parameters
    
    .Parameters
        $cert: The original certificate object.
    
    .Returns
        A hashtable object of public key algorithm and public key parameters.
    #>
    function Compute-PublicKey
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $publicKeyInfo = @{}
    
        $publicKeyInfo["PublicKeyAlgorithm"] = ""
        $publicKeyInfo["PublicKeyParameters"] = ""
    
        if ($cert.PublicKey)
        {
            $publicKeyInfo["PublicKeyAlgorithm"] =  $cert.PublicKey.Oid.FriendlyName
            $publicKeyInfo["PublicKeyParameters"] = $cert.PublicKey.EncodedParameters.Format($true)
        }
    
        $publicKeyInfo
    }
    
    <#
    .Synopsis
        Name: Compute-SignatureAlgorithm
        Description: Computes signature algorithm out of original certificate object.
    
    .Parameters
        $cert: The original certificate object.
    
    .Returns
        The signature algorithm friendly name.
    #>
    function Compute-SignatureAlgorithm
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $signatureAlgorithm = [System.String]::Empty
    
        if ($cert.SignatureAlgorithm)
        {
            $signatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName;
        }
    
        $signatureAlgorithm
    }
    
    <#
    .Synopsis
        Name: Compute-PrivateKeyStatus
        Description: Computes private key exportable status.
    .Parameters
        $hasPrivateKey: A flag indicating certificate has a private key or not.
        $canExportPrivateKey: A flag indicating whether certificate can export a private key.
    
    .Returns
        Enum values "Exported" or "NotExported"
    #>
    function Compute-PrivateKeyStatus
    {
        param (
            [Parameter(Mandatory = $true)]
            [bool]
            $hasPrivateKey,
    
            [Parameter(Mandatory = $true)]
            [bool]
            $canExportPrivateKey
        )
    
        if (-not ($hasPrivateKey))
        {
            $privateKeystatus = "None"
        }
        else
        {
            if ($canExportPrivateKey)
            {
                $privateKeystatus = "Exportable"
            }
            else
            {
                $privateKeystatus = "NotExportable"
            }
        }
    
        $privateKeystatus
    }
    
    <#
    .Synopsis
        Name: Compute-ExpirationStatus
        Description: Computes expiration status based on notAfter date.
    .Parameters
        $notAfter: A date object refering to certificate expiry date.
    
    .Returns
        Enum values "Expired", "NearlyExpired" and "Healthy"
    #>
    function Compute-ExpirationStatus
    {
        param (
            [Parameter(Mandatory = $true)]
            [DateTime]$notAfter
        )
    
        if ([DateTime]::Now -gt $notAfter)
        {
           $expirationStatus = "Expired"
        }
        else
        {
           $nearlyExpired = [DateTime]::Now.AddDays($nearlyExpiredThresholdInDays);
    
           if ($nearlyExpired -ge $notAfter)
           {
              $expirationStatus = "NearlyExpired"
           }
           else
           {
              $expirationStatus = "Healthy"
           }
        }
    
        $expirationStatus
    }
    
    <#
    .Synopsis
        Name: Compute-ArchivedStatus
        Description: Computes archived status of certificate.
    .Parameters
        $archived: A flag to represent archived status.
    
    .Returns
        Enum values "Archived" and "NotArchived"
    #>
    function Compute-ArchivedStatus
    {
        param (
            [Parameter(Mandatory = $true)]
            [bool]
            $archived
        )
    
        if ($archived)
        {
            $archivedStatus = "Archived"
        }
        else
        {
            $archivedStatus = "NotArchived"
        }
    
        $archivedStatus
    }
    
    <#
    .Synopsis
        Name: Compute-IssuedTo
        Description: Computes issued to field out of the certificate subject.
    .Parameters
        $subject: Full subject string of the certificate.
    
    .Returns
        Issued To authority name.
    #>
    function Compute-IssuedTo
    {
        param (
            [String]
            $subject
        )
    
        $issuedTo = [String]::Empty
    
        $issuedToRegex = "CN=(?<issuedTo>[^,?]+)"
        $matched = $subject -match $issuedToRegex
    
        if ($matched -and $Matches)
        {
           $issuedTo = $Matches["issuedTo"]
        }
    
        $issuedTo
    }
    
    <#
    .Synopsis
        Name: Compute-IssuerName
        Description: Computes issuer name of certificate.
    .Parameters
        $cert: The original cert object.
    
    .Returns
        The Issuer authority name.
    #>
    function Compute-IssuerName
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $issuerName = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
    
        $issuerName
    }
    
    <#
    .Synopsis
        Name: Compute-CertificateName
        Description: Computes certificate name of certificate.
    .Parameters
        $cert: The original cert object.
    
    .Returns
        The certificate name.
    #>
    function Compute-CertificateName
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $certificateName = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        if (!$certificateName) {
            $certificateName = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false)
        }
    
        $certificateName
    }
    
    <#
    .Synopsis
        Name: Compute-Store
        Description: Computes certificate store name.
    .Parameters
        $pspath: The full certificate ps path of the certificate.
    
    .Returns
        The certificate store name.
    #>
    function Compute-Store
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $pspath
        )
    
        $pspath.Split('\')[2]
    }
    
    <#
    .Synopsis
        Name: Compute-Scope
        Description: Computes certificate scope/location name.
    .Parameters
        $pspath: The full certificate ps path of the certificate.
    
    .Returns
        The certificate scope/location name.
    #>
    function Compute-Scope
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $pspath
        )
    
        $pspath.Split('\')[1].Split(':')[2]
    }
    
    <#
    .Synopsis
        Name: Compute-Path
        Description: Computes certificate path. E.g. CurrentUser\My\<thumbprint>
    .Parameters
        $pspath: The full certificate ps path of the certificate.
    
    .Returns
        The certificate path.
    #>
    function Compute-Path
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $pspath
        )
    
        $pspath.Split(':')[2]
    }
    
    
    <#
    .Synopsis
        Name: EnhancedKeyUsage-List
        Description: Enhanced KeyUsage
    .Parameters
        $cert: The original cert object.
    
    .Returns
        Enhanced Key Usage.
    #>
    function EnhancedKeyUsage-List
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $usageString = ''
        foreach ( $usage in $cert.EnhancedKeyUsageList){
           $usageString = $usageString + $usage.FriendlyName + ' ' + $usage.ObjectId + "`n"
        }
    
        $usageString
    }
    
    <#
    .Synopsis
        Name: Compute-Template
        Description: Compute template infomation of a certificate
        $certObject: The original certificate object.
    
    .Returns
        The certificate template if there is one otherwise empty string
    #>
    function Compute-Template
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $template = $cert.Extensions | Where-Object {$_.Oid.FriendlyName -match "Template"}
        if ($template) {
            $name = $template.Format(1).split('(')[0]
            if ($name) {
                $name -replace "Template="
            }
            else {
                ''
            }
        }
        else {
            ''
        }
    }
    
    <#
    .Synopsis
        Name: Extract-CertInfo
        Description: Extracts certificate info by decoding different field and create a custom object.
    .Parameters
        $certObject: The original certificate object.
    
    .Returns
        The custom object for certificate.
    #>
    function Extract-CertInfo
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $certObject
        )
    
        $certInfo = @{}
    
        $certInfo["Archived"] = $(Compute-ArchivedStatus $certObject.Archived)
        $certInfo["CertificateName"] = $(Compute-CertificateName $certObject)
    
        $certInfo["EnhancedKeyUsage"] = $(EnhancedKeyUsage-List $certObject) #new
        $certInfo["FriendlyName"] = $certObject.FriendlyName
        $certInfo["IssuerName"] = $(Compute-IssuerName $certObject)
        $certInfo["IssuedTo"] = $(Compute-IssuedTo $certObject.Subject)
        $certInfo["Issuer"] = $certObject.Issuer #new
    
        $certInfo["NotAfter"] = $certObject.NotAfter
        $certInfo["NotBefore"] = $certObject.NotBefore
    
        $certInfo["Path"] = $(Compute-Path  $certObject.PsPath)
        $certInfo["PrivateKey"] =  $(Compute-PrivateKeyStatus -hasPrivateKey $certObject.CalculatedHasPrivateKey -canExportPrivateKey  $certObject.CanExportPrivateKey)
        $publicKeyInfo = $(Compute-PublicKey $certObject)
        $certInfo["PublicKey"] = $publicKeyInfo.PublicKeyAlgorithm
        $certInfo["PublicKeyParameters"] = $publicKeyInfo.PublicKeyParameters
    
        $certInfo["Scope"] = $(Compute-Scope  $certObject.PsPath)
        $certInfo["Store"] = $(Compute-Store  $certObject.PsPath)
        $certInfo["SerialNumber"] = $certObject.SerialNumber
        $certInfo["Subject"] = $certObject.Subject
        $certInfo["Status"] =  $(Compute-ExpirationStatus $certObject.NotAfter)
        $certInfo["SignatureAlgorithm"] = $(Compute-SignatureAlgorithm $certObject)
    
        $certInfo["Thumbprint"] = $certObject.Thumbprint
        $certInfo["Version"] = $certObject.Version
    
        $certInfo["Template"] = $(Compute-Template $certObject)
    
        $certInfo
    }
    
    
    <#############################################################################################
    
        Main script.
    
    #############################################################################################>
    
    
    $certificates =  @()
    
    Get-ChildLeafRecurse $path | foreach {
        $cert = $_
        $cert | Add-Member -Force -NotePropertyName "CalculatedHasPrivateKey" -NotePropertyValue $_.HasPrivateKey
        $exportable = $false
    
        if ($cert.HasPrivateKey)
        {
            [System.Security.Cryptography.CspParameters] $cspParams = new-object System.Security.Cryptography.CspParameters
            $contextField = $cert.GetType().GetField("m_safeCertContext", [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Instance)
            $privateKeyMethod = $cert.GetType().GetMethod("GetPrivateKeyInfo", [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static)
            if ($contextField -and $privateKeyMethod) {
            $contextValue = $contextField.GetValue($cert)
            $privateKeyInfoAvailable = $privateKeyMethod.Invoke($cert, @($ContextValue, $cspParams))
            if ($privateKeyInfoAvailable)
            {
                $PrivateKeyCount++
                $csp = new-object System.Security.Cryptography.CspKeyContainerInfo -ArgumentList @($cspParams)
                if ($csp.Exportable)
                {
                    $exportable = $true
                }
            }
            }
            else
            {
                    $exportable = $true
            }
        }
    
        $cert | Add-Member -Force -NotePropertyName "CanExportPrivateKey" -NotePropertyValue $exportable
    
        $certificates += Extract-CertInfo $cert
    
        }
    
    $certificates
    
}


<#
    
    .SYNOPSIS
        Get Plug and Play device instances by using CIM provider.
    
    .DESCRIPTION
        Get Plug and Play device instances by using CIM provider.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-CimPnpEntity
    
#>
function Get-CimPnpEntity {
    import-module CimCmdlets
    
    Get-CimInstance -Namespace root/cimv2 -ClassName Win32_PnPEntity   
}


<#
    
    .SYNOPSIS
        Gets 'Machine' and 'User' environment variables.
    
    .DESCRIPTION
        Gets 'Machine' and 'User' environment variables.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-EnvironmentVariables
    
#>
function Get-EnvironmentVariables {
    Set-StrictMode -Version 5.0
    
    $data = @()
    
    $system = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Machine)
    $user = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::User)
    
    foreach ($h in $system.GetEnumerator()) {
        $obj = [pscustomobject]@{"Name" = $h.Name; "Value" = $h.Value; "Type" = "Machine"}
        $data += $obj
    }
    
    foreach ($h in $user.GetEnumerator()) {
        $obj = [pscustomobject]@{"Name" = $h.Name; "Value" = $h.Value; "Type" = "User"}
        $data += $obj
    }
    
    $data
}


<#
    
    .SYNOPSIS
        Get the log summary (Name, Total) for the channel selected by using Get-WinEvent cmdlet.
    
    .DESCRIPTION
        Get the log summary (Name, Total) for the channel selected by using Get-WinEvent cmdlet.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
    .PARAMETER channel
        This parameter is OPTIONAL.

        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-EventLogSummary
    
#>
function Get-EventLogSummary {
    Param(
        [string]$channel
    )
    
    $ErrorActionPreference = 'SilentlyContinue'
    
    Import-Module Microsoft.PowerShell.Diagnostics;
    
    $channelList = $channel.split(",")
    
    Get-WinEvent -ListLog $channelList -Force -ErrorAction SilentlyContinue
}


<#
    
    .SYNOPSIS
        Get settings that apply to the per-profile configurations of the Windows Firewall with Advanced Security.
    
    .DESCRIPTION
        Get settings that apply to the per-profile configurations of the Windows Firewall with Advanced Security.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-FirewallProfile
    
#>
function Get-FirewallProfile {
    Import-Module netsecurity
    
    Get-NetFirewallProfile -PolicyStore ActiveStore | Microsoft.PowerShell.Utility\Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
}


<#
    
    .SYNOPSIS
        Get Firewall Rules.
    
    .DESCRIPTION
        Get Firewall Rules.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-FirewallRules
    
#>
function Get-FirewallRules {
    Import-Module netsecurity
    
    $sidToPrincipalCache = @{};
    
    function getPrincipalForSid($sid) {
    
        if ($sidToPrincipalCache.ContainsKey($sid)) {
        return $sidToPrincipalCache[$sid]
        }
    
        $propertyBag = @{}
        $propertyBag.userName = ""
        $propertyBag.domain = ""
        $propertyBag.principal = ""
        $propertyBag.ssid = $sid
    
        try{
            $win32Sid = [WMI]"root\cimv2:win32_sid.sid='$sid'";
        $propertyBag.userName = $win32Sid.AccountName;
        $propertyBag.domain = $win32Sid.ReferencedDomainName
    
        try {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
            try{
            $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
            $propertyBag.principal = $objUser.Value;
            } catch [System.Management.Automation.MethodInvocationException]{
            # the sid couldn't be resolved
            }
    
        } catch [System.Management.Automation.MethodInvocationException]{
            # the sid is invalid
        }
    
        } catch [System.Management.Automation.RuntimeException] {
        # failed to get the user info, which is ok, maybe an old SID
        }
    
        $object = New-Object -TypeName PSObject -Prop $propertyBag
        $sidToPrincipalCache.Add($sid, $object)
    
        return $object
    }
    
    function fillUserPrincipalsFromSddl($sddl, $allowedPrincipals, $skippedPrincipals) {
        if ($sddl -eq $null -or $sddl.count -eq 0) {
        return;
        }
    
        $entries = $sddl.split(@("(", ")"));
        foreach ($entry in $entries) {
        $entryChunks = $entry.split(";");
        $sid = $entryChunks[$entryChunks.count - 1];
        if ($entryChunks[0] -eq "A") {
            $allowed = getPrincipalForSid($sid);
            $allowedPrincipals.Add($allowed) > $null;
        } elseif ($entryChunks[0] -eq "D") {
            $skipped = getPrincipalForSid($sid);
            $skippedPrincipals.Add($skipped) > $null;
        }
        }
    }
    
    $stores = @('PersistentStore','RSOP');
    $allRules = @()
    foreach ($store in $stores){
        $rules = (Get-NetFirewallRule -PolicyStore $store)
    
        $rulesHash = @{}
        $rules | foreach {
        $newRule = ($_ | Microsoft.PowerShell.Utility\Select-Object `
            instanceId, `
            name, `
            displayName, `
            description, `
            displayGroup, `
            group, `
            @{Name="enabled"; Expression={$_.Enabled -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::True}}, `
            profiles, `
            platform, `
            direction, `
            action, `
            edgeTraversalPolicy, `
            looseSourceMapping, `
            localOnlyMapping, `
            owner, `
            primaryStatus, `
            status, `
            enforcementStatus, `
            policyStoreSource, `
            policyStoreSourceType, `
            @{Name="policyStore"; Expression={$store}}, `
            @{Name="addressFilter"; Expression={""}}, `
            @{Name="applicationFilter"; Expression={""}}, `
            @{Name="interfaceFilter"; Expression={""}}, `
            @{Name="interfaceTypeFilter"; Expression={""}}, `
            @{Name="portFilter"; Expression={""}}, `
            @{Name="securityFilter"; Expression={""}}, `
            @{Name="serviceFilter"; Expression={""}})
    
            $rulesHash[$_.CreationClassName] = $newRule
            $allRules += $newRule  }
    
        $addressFilters = (Get-NetFirewallAddressFilter  -PolicyStore $store)
        $applicationFilters = (Get-NetFirewallApplicationFilter  -PolicyStore $store)
        $interfaceFilters = (Get-NetFirewallInterfaceFilter  -PolicyStore $store)
        $interfaceTypeFilters = (Get-NetFirewallInterfaceTypeFilter  -PolicyStore  $store)
        $portFilters = (Get-NetFirewallPortFilter  -PolicyStore $store)
        $securityFilters = (Get-NetFirewallSecurityFilter  -PolicyStore $store)
        $serviceFilters = (Get-NetFirewallServiceFilter  -PolicyStore $store)
    
        $addressFilters | ForEach-Object {
        $newAddressFilter = $_ | Microsoft.PowerShell.Utility\Select-Object localAddress, remoteAddress;
        $newAddressFilter.localAddress = @($newAddressFilter.localAddress)
        $newAddressFilter.remoteAddress = @($newAddressFilter.remoteAddress)
        $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.addressFilter = $newAddressFilter
        }
        }
    
        $applicationFilters | ForEach-Object {
        $newApplicationFilter = $_ | Microsoft.PowerShell.Utility\Select-Object program, package;
            $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.applicationFilter = $newApplicationFilter
        }
        }
    
        $interfaceFilters | ForEach-Object {
        $newInterfaceFilter = $_ | Microsoft.PowerShell.Utility\Select-Object @{Name="interfaceAlias"; Expression={}};
        $newInterfaceFilter.interfaceAlias = @($_.interfaceAlias);
            $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.interfaceFilter = $newInterfaceFilter
        }
        }
    
        $interfaceTypeFilters | foreach {
        $newInterfaceTypeFilter  = $_ | Microsoft.PowerShell.Utility\Select-Object @{Name="interfaceType"; Expression={}};
        $newInterfaceTypeFilter.interfaceType = $_.PSbase.CimInstanceProperties["InterfaceType"].Value;
        $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.interfaceTypeFilter = $newInterfaceTypeFilter
        }
        }
    
        $portFilters | foreach {
        $newPortFilter = $_ | Microsoft.PowerShell.Utility\Select-Object dynamicTransport, icmpType, localPort, remotePort, protocol;
        $newPortFilter.localPort = @($newPortFilter.localPort);
        $newPortFilter.remotePort = @($newPortFilter.remotePort);
        $newPortFilter.icmpType = @($newPortFilter.icmpType);
        $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.portFilter = $newPortFilter
        }
        }
    
        $securityFilters | ForEach-Object {
        $allowedLocalUsers = New-Object System.Collections.ArrayList;
        $skippedLocalUsers = New-Object System.Collections.ArrayList;
        fillUserPrincipalsFromSddl -sddl $_.localUser -allowedprincipals $allowedLocalUsers -skippedPrincipals $skippedLocalUsers;
    
        $allowedRemoteMachines = New-Object System.Collections.ArrayList;
        $skippedRemoteMachines = New-Object System.Collections.ArrayList;
        fillUserPrincipalsFromSddl -sddl $_.remoteMachine -allowedprincipals $allowedRemoteMachines -skippedPrincipals $skippedRemoteMachines;
    
        $allowedRemoteUsers = New-Object System.Collections.ArrayList;
        $skippedRemoteUsers = New-Object System.Collections.ArrayList;
        fillUserPrincipalsFromSddl -sddl $_.remoteUser -allowedprincipals $allowedRemoteUsers -skippedPrincipals $skippedRemoteUsers;
    
        $newSecurityFilter = $_ | Microsoft.PowerShell.Utility\Select-Object authentication, `
        encryption, `
        overrideBlockRules, `
        @{Name="allowedLocalUsers"; Expression={}}, `
        @{Name="skippedLocalUsers"; Expression={}}, `
        @{Name="allowedRemoteMachines"; Expression={}}, `
        @{Name="skippedRemoteMachines"; Expression={}}, `
        @{Name="allowedRemoteUsers"; Expression={}}, `
        @{Name="skippedRemoteUsers"; Expression={}};
    
        $newSecurityFilter.allowedLocalUsers = $allowedLocalUsers.ToArray()
        $newSecurityFilter.skippedLocalUsers = $skippedLocalUsers.ToArray()
        $newSecurityFilter.allowedRemoteMachines = $allowedRemoteMachines.ToArray()
        $newSecurityFilter.skippedRemoteMachines = $skippedRemoteMachines.ToArray()
        $newSecurityFilter.allowedRemoteUsers = $allowedRemoteUsers.ToArray()
        $newSecurityFilter.skippedRemoteUsers = $skippedRemoteUsers.ToArray()
    
        $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.securityFilter = $newSecurityFilter
        }
        }
    
        $serviceFilters | ForEach-Object {
        $newServiceFilter = $_ | Microsoft.PowerShell.Utility\Select-Object serviceName;
        $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.serviceFilter = $newServiceFilter
        }
        }
    }
    
    $allRules
    
}


<#
    
    .SYNOPSIS
        Get all IPs within the specified range.
    
    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER start
        This parameter is OPTIONAL.

        TODO

    .PARAMETER end
        This parameter is OPTIONAL.

        TODO

    .PARAMETER ip
        This parameter is OPTIONAL.

        TODO

    .PARAMETER mask
        This parameter is OPTIONAL.

        TODO

    .PARAMETER cidr
        This parameter is OPTIONAL.

        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-IPRange -Start 192.168.2.4 -End 192.168.2.50
    
#>

function Get-IPRange {
    [CmdletBinding()]
    param ( 
        [string]$start, 
        [string]$end, 
        [string]$ip, 
        [string]$mask, 
        [int]$cidr 
    ) 
    
    function IP-toINT64 () { 
        param ($ip) 
    
        $octets = $ip.split(".") 
        return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3]) 
    } 
    
    function INT64-toIP() { 
        param ([int64]$int) 
    
        return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )
    } 
    
    if ($ip) {$ipaddr = [Net.IPAddress]::Parse($ip)} 
    if ($cidr) {$maskaddr = [Net.IPAddress]::Parse((INT64-toIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2)))) } 
    if ($mask) {$maskaddr = [Net.IPAddress]::Parse($mask)} 
    if ($ip) {$networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)} 
    if ($ip) {$broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))} 
    
    if ($ip) { 
        $startaddr = IP-toINT64 -ip $networkaddr.ipaddresstostring 
        $endaddr = IP-toINT64 -ip $broadcastaddr.ipaddresstostring 
    } else { 
        $startaddr = IP-toINT64 -ip $start 
        $endaddr = IP-toINT64 -ip $end 
    }
    
    for ($i = $startaddr; $i -le $endaddr; $i++) {
        INT64-toIP -int $i
    }
}


<#
    
    .SYNOPSIS
        Gets the local groups.
    
    .DESCRIPTION
        Gets the local groups. The supported Operating Systems are Window Server 2012,
        Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers

    .PARAMETER SID
        This parameter is OPTIONAL.

        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-LocalGroups
    
#>
function Get-LocalGroups {
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $SID
    )
    
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue
    
    $isWinServer2016OrNewer = [Environment]::OSVersion.Version.Major -ge 10;
    # ADSI does NOT support 2016 Nano, meanwhile New-LocalUser, Get-LocalUser, Set-LocalUser do NOT support downlevel
    if ($SID)
    {
        if ($isWinServer2016OrNewer)
        {
            Get-LocalGroup -SID $SID | Select-Object Description,Name,SID,ObjectClass | foreach {
                [pscustomobject]@{
                    Description         = $_.Description
                    Name                = $_.Name
                    SID                 = $_.SID.Value
                    ObjectClass         = $_.ObjectClass
                    Members             = Get-LocalGroupUsers -group $_.Name
                }
            }
        }
        else
        {
            Get-WmiObject -Class Win32_Group -Filter "LocalAccount='True' AND SID='$SID'" | Select-Object Description,Name,SID,ObjectClass | foreach {
                [pscustomobject]@{
                    Description         = $_.Description
                    Name                = $_.Name
                    SID                 = $_.SID
                    ObjectClass         = $_.ObjectClass
                    Members             = Get-LocalGroupUsers -group $_.Name
                }
            }
        }
    }
    else
    {
        if ($isWinServer2016OrNewer)
        {
            Get-LocalGroup | Microsoft.PowerShell.Utility\Select-Object Description,Name,SID,ObjectClass | foreach {
                [pscustomobject]@{
                    Description         = $_.Description
                    Name                = $_.Name
                    SID                 = $_.SID.Value
                    ObjectClass         = $_.ObjectClass
                    Members             = Get-LocalGroupUsers -group $_.Name
                }
            }
        }
        else
        {
            Get-WmiObject -Class Win32_Group -Filter "LocalAccount='True'" | Microsoft.PowerShell.Utility\Select-Object Description,Name,SID,ObjectClass | foreach {
                [pscustomobject]@{
                    Description         = $_.Description
                    Name                = $_.Name
                    SID                 = $_.SID
                    ObjectClass         = $_.ObjectClass
                    Members             = Get-LocalGroupUsers -group $_.Name
                }
            }
        }
    }    
}


<#
    
    .SYNOPSIS
        Get users belong to group.
    
    .DESCRIPTION
        Get users belong to group. The supported Operating Systems are Window Server 2012,
        Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers

    .PARAMETER group
        This parameter is MANDATORY.

        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-LocalGroupUsers -group Administrators
    
#>
function Get-LocalGroupUsers {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $group
    )
    
    # ADSI does NOT support 2016 Nano, meanwhile Get-LocalGroupMember does NOT support downlevel and also has bug
    $ComputerName = $env:COMPUTERNAME
    try {
        $groupconnection = [ADSI]("WinNT://localhost/$group,group")
        $contents = $groupconnection.Members() | ForEach-Object {
            $path=$_.GetType().InvokeMember("ADsPath", "GetProperty", $NULL, $_, $NULL)
            # $path will looks like:
            #   WinNT://ComputerName/Administrator
            #   WinNT://DomainName/Domain Admins
            # Find out if this is a local or domain object and trim it accordingly
            if ($path -like "*/$ComputerName/*"){
                $start = 'WinNT://' + $ComputerName + '/'
            }
            else {
                $start = 'WinNT://'
            }
            $name = $path.Substring($start.length)
            $name.Replace('/', '\') #return name here
        }
        return $contents
    }
    catch { # if above block failed (say in 2016Nano), use another cmdlet
        # clear existing error info from try block
        $Error.Clear()
        #There is a known issue, in some situation Get-LocalGroupMember return: Failed to compare two elements in the array.
        $contents = Get-LocalGroupMember -group $group
        $names = $contents.Name | ForEach-Object {
            $name = $_
            if ($name -like "$ComputerName\*") {
                $name = $name.Substring($ComputerName.length+1)
            }
            $name
        }
        return $names
    }
    
}


<#
    
    .SYNOPSIS
        Get a local user belong to group list.
    
    .DESCRIPTION
        Get a local user belong to group list. The supported Operating Systems are
        Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers

    .PARAMETER UserName
        This parameter is MANDATORY.

        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-LocalUserBelongGroups -UserName jsmith
    
#>
function Get-LocalUserBelongGroups {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $UserName
    )
    
    Import-Module CimCmdlets -ErrorAction SilentlyContinue
    
    $operatingSystem = Get-CimInstance Win32_OperatingSystem
    $version = [version]$operatingSystem.Version
    # product type 3 is server, version number ge 10 is server 2016
    $isWinServer2016OrNewer = ($operatingSystem.ProductType -eq 3) -and ($version -ge '10.0')
    
    # ADSI does NOT support 2016 Nano, meanwhile net localgroup do NOT support downlevel "net : System error 1312 has occurred."
    
    # Step 1: get the list of local groups
    if ($isWinServer2016OrNewer) {
        $grps = net localgroup | Where-Object {$_ -AND $_ -match "^[*]"}  # group member list as "*%Fws\r\n"
        $groups = $grps.trim('*')
    }
    else {
        $grps = Get-WmiObject -Class Win32_Group -Filter "LocalAccount='True'" | Microsoft.PowerShell.Utility\Select-Object Name
        $groups = $grps.Name
    }
    
    # Step 2: in each group, list members and find match to target $UserName
    $groupNames = @()
    $regex = '^' + $UserName + '\b'
    foreach ($group in $groups) {
        $found = $false
        #find group members
        if ($isWinServer2016OrNewer) {
            $members = net localgroup $group | Where-Object {$_ -AND $_ -notmatch "command completed successfully"} | Microsoft.PowerShell.Utility\Select-Object -skip 4
            if ($members -AND $members.contains($UserName)) {
                $found = $true
            }
        }
        else {
            $groupconnection = [ADSI]("WinNT://localhost/$group,group")
            $members = $groupconnection.Members()
            ForEach ($member in $members) {
                $name = $member.GetType().InvokeMember("Name", "GetProperty", $NULL, $member, $NULL)
                if ($name -AND ($name -match $regex)) {
                    $found = $true
                    break
                }
            }
        }
        #if members contains $UserName, add group name to list
        if ($found) {
            $groupNames = $groupNames + $group
        }
    }
    return $groupNames
    
}


<#
    
    .SYNOPSIS
        Gets the local users.
    
    .DESCRIPTION
        Gets the local users. The supported Operating Systems are
        Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers

    .PARAMETER SID
        This parameter is OPTIONAL.

        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-LocalUsers
    
#>
function Get-LocalUsers {
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $SID
    )
    
    $isWinServer2016OrNewer = [Environment]::OSVersion.Version.Major -ge 10;
    # ADSI does NOT support 2016 Nano, meanwhile New-LocalUser, Get-LocalUser, Set-LocalUser do NOT support downlevel
    if ($SID)
    {
        if ($isWinServer2016OrNewer)
        {
            Get-LocalUser -SID $SID | Microsoft.PowerShell.Utility\Select-Object @(
                "AccountExpires",
                "Description",
                "Enabled",
                "FullName",
                "LastLogon",
                "Name",
                "ObjectClass",
                "PasswordChangeableDate",
                "PasswordExpires",
                "PasswordLastSet",
                "PasswordRequired",
                "SID",
                "UserMayChangePassword"
            ) | foreach {
                [pscustomobject]@{
                    AccountExpires          = $_.AccountExpires
                    Description             = $_.Description
                    Enabled                 = $_.Enabled
                    FullName                = $_.FullName
                    LastLogon               = $_.LastLogon
                    Name                    = $_.Name
                    GroupMembership         = Get-LocalUserBelongGroups -UserName $_.Name
                    ObjectClass             = $_.ObjectClass
                    PasswordChangeableDate  = $_.PasswordChangeableDate
                    PasswordExpires         = $_.PasswordExpires
                    PasswordLastSet         = $_.PasswordLastSet
                    PasswordRequired        = $_.PasswordRequired
                    SID                     = $_.SID.Value
                    UserMayChangePassword   = $_.UserMayChangePassword
                }
            }
        }
        else
        {
            Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' AND SID='$SID'" | Microsoft.PowerShell.Utility\Select-Object @(
                "AccountExpirationDate",
                "Description",
                "Disabled"
                "FullName",
                "LastLogon",
                "Name",
                "ObjectClass",
                "PasswordChangeableDate",
                "PasswordExpires",
                "PasswordLastSet",
                "PasswordRequired",
                "SID",
                "PasswordChangeable"
            ) | foreach {
                [pscustomobject]@{
                    AccountExpires          = $_.AccountExpirationDate
                    Description             = $_.Description
                    Enabled                 = !$_.Disabled
                    FullName                = $_.FullName
                    LastLogon               = $_.LastLogon
                    Name                    = $_.Name
                    GroupMembership         = Get-LocalUserBelongGroups -UserName $_.Name
                    ObjectClass             = $_.ObjectClass
                    PasswordChangeableDate  = $_.PasswordChangeableDate
                    PasswordExpires         = $_.PasswordExpires
                    PasswordLastSet         = $_.PasswordLastSet
                    PasswordRequired        = $_.PasswordRequired
                    SID                     = $_.SID.Value
                    UserMayChangePassword   = $_.PasswordChangeable
                }
            }
        }
    }
    else
    {
        if ($isWinServer2016OrNewer)
        {
            Get-LocalUser | Microsoft.PowerShell.Utility\Select-Object @(
                "AccountExpires",
                "Description",
                "Enabled",
                "FullName",
                "LastLogon",
                "Name",
                "ObjectClass",
                "PasswordChangeableDate",
                "PasswordExpires",
                "PasswordLastSet",
                "PasswordRequired",
                "SID",
                "UserMayChangePassword"
            ) | foreach {
                [pscustomobject]@{
                    AccountExpires          = $_.AccountExpires
                    Description             = $_.Description
                    Enabled                 = $_.Enabled
                    FullName                = $_.FullName
                    LastLogon               = $_.LastLogon
                    Name                    = $_.Name
                    GroupMembership         = Get-LocalUserBelongGroups -UserName $_.Name
                    ObjectClass             = $_.ObjectClass
                    PasswordChangeableDate  = $_.PasswordChangeableDate
                    PasswordExpires         = $_.PasswordExpires
                    PasswordLastSet         = $_.PasswordLastSet
                    PasswordRequired        = $_.PasswordRequired
                    SID                     = $_.SID.Value
                    UserMayChangePassword   = $_.UserMayChangePassword
                }
            }
        }
        else
        {
            Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Microsoft.PowerShell.Utility\Select-Object @(
                "AccountExpirationDate",
                "Description",
                "Disabled"
                "FullName",
                "LastLogon",
                "Name",
                "ObjectClass",
                "PasswordChangeableDate",
                "PasswordExpires",
                "PasswordLastSet",
                "PasswordRequired",
                "SID",
                "PasswordChangeable"
            ) | foreach {
                [pscustomobject]@{
                    AccountExpires          = $_.AccountExpirationDate
                    Description             = $_.Description
                    Enabled                 = !$_.Disabled
                    FullName                = $_.FullName
                    LastLogon               = $_.LastLogon
                    Name                    = $_.Name
                    GroupMembership         = Get-LocalUserBelongGroups -UserName $_.Name
                    ObjectClass             = $_.ObjectClass
                    PasswordChangeableDate  = $_.PasswordChangeableDate
                    PasswordExpires         = $_.PasswordExpires
                    PasswordLastSet         = $_.PasswordLastSet
                    PasswordRequired        = $_.PasswordRequired
                    SID                     = $_.SID.Value
                    UserMayChangePassword   = $_.PasswordChangeable
                }
            }
        }
    }    
}


<#
    .SYNOPSIS
        Get all information about interfaces on your local machine

    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER InterfaceStatus
        This parameter is OPTIONAL.
        
        This parameter takes a string that has a value of either "Up" or "Down".

    .PARAMETER AddressFamily
        This parameter is OPTIONAL.

        This parameter takes a string that has a value of either "IPv4" or "IPv6"

    .EXAMPLE
        # On Windows
        PS C:\Users\testadmin> Get-NetworkInfo interfaceStatus "Up" -AddressFamily "IPv4"

    .EXAMPLE
        # On Linux
        PS /home/pdadmin/Downloads> Get-NetworkInfo interfaceStatus "Up" -AddressFamily "IPv4"
#>
function Get-NetworkInfo {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$False)]
        [ValidateSet("Up","Down")]
        [string]$InterfaceStatus,

        [Parameter(Mandatory=$False)]
        [ValidateSet("IPv4","IPv6")]
        [string]$AddressFamily
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($AddressFamily) {
        if ($AddressFamily -eq "IPv4") {
            $AddrFam = "InterNetwork"
        }
        if ($AddressFamily -eq "IPv6") {
            $AddrFam = "InterNetworkV6"
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    [System.Collections.Arraylist]$PSObjectCollection = @()
    $interfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()

    $InterfacesToExplore = $interfaces
    if ($InterfaceStatus) {
        $InterfacesToExplore = $InterfacesToExplore | Where-Object {$_.OperationalStatus -eq $InterfaceStatus}
    }
    if ($AddressFamily) {
        $InterfacesToExplore = $InterfacesToExplore | Where-Object {$($_.GetIPProperties().UnicastAddresses | foreach {$_.Address.AddressFamily}) -contains $AddrFam}
    }

    foreach ($adapter in $InterfacesToExplore) {
        $ipprops = $adapter.GetIPProperties()
        $ippropsPropertyNames = $($ipprops | Get-Member -MemberType Property).Name

        if ($AddressFamily) {
            $UnicastAddressesToExplore = $ipprops.UnicastAddresses | Where-Object {$_.Address.AddressFamily -eq $AddrFam}
        }
        else {
            $UnicastAddressesToExplore = $ipprops.UnicastAddresses
        }

        foreach ($ip in $UnicastAddressesToExplore) {
            $FinalPSObject = [pscustomobject]@{}
            
            $adapterPropertyNames = $($adapter | Get-Member -MemberType Property).Name
            foreach ($adapterPropName in $adapterPropertyNames) {
                $FinalPSObjectMemberCheck = $($FinalPSObject | Get-Member -MemberType NoteProperty).Name
                if ($FinalPSObjectMemberCheck -notcontains $adapterPropName) {
                    $FinalPSObject | Add-Member -MemberType NoteProperty -Name $adapterPropName -Value $($adapter.$adapterPropName)
                }
            }
            
            foreach ($ippropsPropName in $ippropsPropertyNames) {
                $FinalPSObjectMemberCheck = $($FinalPSObject | Get-Member -MemberType NoteProperty).Name
                if ($FinalPSObjectMemberCheck -notcontains $ippropsPropName -and
                $ippropsPropName -ne "UnicastAddresses" -and $ippropsPropName -ne "MulticastAddresses") {
                    $FinalPSObject | Add-Member -MemberType NoteProperty -Name $ippropsPropName -Value $($ipprops.$ippropsPropName)
                }
            }
                
            $ipUnicastPropertyNames = $($ip | Get-Member -MemberType Property).Name
            foreach ($UnicastPropName in $ipUnicastPropertyNames) {
                $FinalPSObjectMemberCheck = $($FinalPSObject | Get-Member -MemberType NoteProperty).Name
                if ($FinalPSObjectMemberCheck -notcontains $UnicastPropName) {
                    $FinalPSObject | Add-Member -MemberType NoteProperty -Name $UnicastPropName -Value $($ip.$UnicastPropName)
                }
            }
            
            $null = $PSObjectCollection.Add($FinalPSObject)
        }
    }

    $PSObjectCollection

    ##### END Main Body #####
        
}


<#
    .SYNOPSIS
        Gets the network ip configuration.
    
    .DESCRIPTION
        Gets the network ip configuration. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-Certificates -path "Cert:\" -nearlyExpiredThresholdInDays 60

#>
function Get-Networks {
    Import-Module NetAdapter
    Import-Module NetTCPIP
    Import-Module DnsClient
    
    Set-StrictMode -Version 5.0
    $ErrorActionPreference = 'SilentlyContinue'
    
    # Get all net information
    $netAdapter = Get-NetAdapter
    
    # conditions used to select the proper ip address for that object modeled after ibiza method.
    # We only want manual (set by user manually), dhcp (set up automatically with dhcp), or link (set from link address)
    # fe80 is the prefix for link local addresses, so that is the format want if the suffix origin is link
    # SkipAsSource -eq zero only grabs ip addresses with skipassource set to false so we only get the preffered ip address
    $ipAddress = Get-NetIPAddress | Where-Object {
        ($_.SuffixOrigin -eq 'Manual') -or
        ($_.SuffixOrigin -eq 'Dhcp') -or 
        (($_.SuffixOrigin -eq 'Link') -and (($_.IPAddress.StartsWith('fe80:')) -or ($_.IPAddress.StartsWith('2001:'))))
    }
    
    $netIPInterface = Get-NetIPInterface
    $netRoute = Get-NetRoute -PolicyStore ActiveStore
    $dnsServer = Get-DnsClientServerAddress
    
    # Load in relevant net information by name
    Foreach ($currentNetAdapter in $netAdapter) {
        $result = New-Object PSObject
    
        # Net Adapter information
        $result | Add-Member -MemberType NoteProperty -Name 'InterfaceAlias' -Value $currentNetAdapter.InterfaceAlias
        $result | Add-Member -MemberType NoteProperty -Name 'InterfaceIndex' -Value $currentNetAdapter.InterfaceIndex
        $result | Add-Member -MemberType NoteProperty -Name 'InterfaceDescription' -Value $currentNetAdapter.InterfaceDescription
        $result | Add-Member -MemberType NoteProperty -Name 'Status' -Value $currentNetAdapter.Status
        $result | Add-Member -MemberType NoteProperty -Name 'MacAddress' -Value $currentNetAdapter.MacAddress
        $result | Add-Member -MemberType NoteProperty -Name 'LinkSpeed' -Value $currentNetAdapter.LinkSpeed
    
        # Net IP Address information
        # Primary addresses are used for outgoing calls so SkipAsSource is false (0)
        # Should only return one if properly configured, but it is possible to set multiple, so collect all
        $primaryIPv6Addresses = $ipAddress | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv6') -and ($_.SkipAsSource -eq 0)}
        if ($primaryIPv6Addresses) {
            $ipArray = New-Object System.Collections.ArrayList
            $linkLocalArray = New-Object System.Collections.ArrayList
            Foreach ($address in $primaryIPv6Addresses) {
                if ($address -ne $null -and $address.IPAddress -ne $null -and $address.IPAddress.StartsWith('fe80')) {
                    $linkLocalArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
                }
                else {
                    $ipArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
                }
            }
            $result | Add-Member -MemberType NoteProperty -Name 'PrimaryIPv6Address' -Value $ipArray
            $result | Add-Member -MemberType NoteProperty -Name 'LinkLocalIPv6Address' -Value $linkLocalArray
        }
    
        $primaryIPv4Addresses = $ipAddress | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv4') -and ($_.SkipAsSource -eq 0)}
        if ($primaryIPv4Addresses) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $primaryIPv4Addresses) {
                $ipArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
            }
            $result | Add-Member -MemberType NoteProperty -Name 'PrimaryIPv4Address' -Value $ipArray
        }
    
        # Secondary addresses are not used for outgoing calls so SkipAsSource is true (1)
        # There will usually not be secondary addresses, but collect them just in case
        $secondaryIPv6Adresses = $ipAddress | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv6') -and ($_.SkipAsSource -eq 1)}
        if ($secondaryIPv6Adresses) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $secondaryIPv6Adresses) {
                $ipArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
            }
            $result | Add-Member -MemberType NoteProperty -Name 'SecondaryIPv6Address' -Value $ipArray
        }
    
        $secondaryIPv4Addresses = $ipAddress | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv4') -and ($_.SkipAsSource -eq 1)}
        if ($secondaryIPv4Addresses) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $secondaryIPv4Addresses) {
                $ipArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
            }
            $result | Add-Member -MemberType NoteProperty -Name 'SecondaryIPv4Address' -Value $ipArray
        }
    
        # Net IP Interface information
        $currentDhcpIPv4 = $netIPInterface | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv4')}
        if ($currentDhcpIPv4) {
            $result | Add-Member -MemberType NoteProperty -Name 'DhcpIPv4' -Value $currentDhcpIPv4.Dhcp
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4Enabled' -Value $true
        }
        else {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4Enabled' -Value $false
        }
    
        $currentDhcpIPv6 = $netIPInterface | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv6')}
        if ($currentDhcpIPv6) {
            $result | Add-Member -MemberType NoteProperty -Name 'DhcpIPv6' -Value $currentDhcpIPv6.Dhcp
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6Enabled' -Value $true
        }
        else {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6Enabled' -Value $false
        }
    
        # Net Route information
        # destination prefix for selected ipv6 address is always ::/0
        $currentIPv6DefaultGateway = $netRoute | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.DestinationPrefix -eq '::/0')}
        if ($currentIPv6DefaultGateway) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $currentIPv6DefaultGateway) {
                if ($address.NextHop) {
                    $ipArray.Add($address.NextHop) > $null
                }
            }
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6DefaultGateway' -Value $ipArray
        }
    
        # destination prefix for selected ipv4 address is always 0.0.0.0/0
        $currentIPv4DefaultGateway = $netRoute | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.DestinationPrefix -eq '0.0.0.0/0')}
        if ($currentIPv4DefaultGateway) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $currentIPv4DefaultGateway) {
                if ($address.NextHop) {
                    $ipArray.Add($address.NextHop) > $null
                }
            }
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4DefaultGateway' -Value $ipArray
        }
    
        # DNS information
        # dns server util code for ipv4 is 2
        $currentIPv4DnsServer = $dnsServer | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 2)}
        if ($currentIPv4DnsServer) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $currentIPv4DnsServer) {
                if ($address.ServerAddresses) {
                    $ipArray.Add($address.ServerAddresses) > $null
                }
            }
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4DNSServer' -Value $ipArray
        }
    
        # dns server util code for ipv6 is 23
        $currentIPv6DnsServer = $dnsServer | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 23)}
        if ($currentIPv6DnsServer) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $currentIPv6DnsServer) {
                if ($address.ServerAddresses) {
                    $ipArray.Add($address.ServerAddresses) > $null
                }
            }
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6DNSServer' -Value $ipArray
        }
    
        $adapterGuid = $currentNetAdapter.InterfaceGuid
        if ($adapterGuid) {
          $regPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($adapterGuid)"
          $ipv4Properties = Get-ItemProperty $regPath
          if ($ipv4Properties -and $ipv4Properties.NameServer) {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4DnsManuallyConfigured' -Value $true
          } else {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4DnsManuallyConfigured' -Value $false
          }
    
          $regPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$($adapterGuid)"
          $ipv6Properties = Get-ItemProperty $regPath
          if ($ipv6Properties -and $ipv6Properties.NameServer) {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6DnsManuallyConfigured' -Value $true
          } else {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6DnsManuallyConfigured' -Value $false
          }
        }
    
        $result
    }
    
}


<#    
    .SYNOPSIS   
        Retrieves the updates waiting to be installed from WSUS
        
    .DESCRIPTION   
        Retrieves the updates waiting to be installed from WSUS
        
    .PARAMETER Computername 
        Computer or computers to find updates for.

    .EXAMPLE   
        Get-PendingUpdates 

        Description
        -----------
        Retrieves the updates that are available to install on the local system
    
    .NOTES
        Author: Boe Prox
#>
Function Get-PendingUpdates {
    [CmdletBinding(DefaultParameterSetName = 'computer')] 
    Param ( 
        [Parameter(ValueFromPipeline = $True)] 
        [string[]]$ComputerName = $env:COMPUTERNAME
    )

    Process {
        foreach ($computer in $Computername) {
            If (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
                Try {
                    # Create Session COM object
                    Write-Verbose "Creating COM object for WSUS Session"
                    $updatesession =  [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session",$computer))
                }
                Catch {
                    Write-Warning "$($Error[0])"
                    Break
                } 
 
                # Configure Session COM Object
                Write-Verbose "Creating COM object for WSUS update Search"
                $updatesearcher = $updatesession.CreateUpdateSearcher()
 
                # Configure Searcher object to look for Updates awaiting installation
                Write-Verbose "Searching for WSUS updates on client"
                $searchresult = $updatesearcher.Search("IsInstalled=0")
             
                # Verify if Updates need installed
                Write-Verbose "Verifing that updates are available to install"
                If ($searchresult.Updates.Count -gt 0) {
                    # Updates are waiting to be installed
                    Write-Verbose "Found $($searchresult.Updates.Count) update\s!"
                    # Cache the count to make the For loop run faster
                    $count = $searchresult.Updates.Count
                 
                    # Begin iterating through Updates available for installation
                    Write-Verbose "Iterating through list of updates"
                    For ($i=0; $i -lt $Count; $i++) {
                        # Create object holding update
                        $Update = $searchresult.Updates.Item($i)
                        [pscustomobject]@{
                            Computername        = $Computer
                            Title               = $Update.Title
                            KB                  = $($Update.KBArticleIDs)
                            SecurityBulletin    = $($Update.SecurityBulletinIDs)
                            MsrcSeverity        = $Update.MsrcSeverity
                            IsDownloaded        = $Update.IsDownloaded
                            Url                 = $($Update.MoreInfoUrls)
                            Categories          = ($Update.Categories | Select-Object -ExpandProperty Name)
                            BundledUpdates      = @($Update.BundledUpdates) | foreach {
                               [pscustomobject]@{
                                    Title = $_.Title
                                    DownloadUrl = @($_.DownloadContents).DownloadUrl
                                }
                            }
                        } 
                    }
                } 
                Else { 
                    #Nothing to install at this time
                    Write-Verbose "No updates to install."
                }
            }
            Else {
                #Nothing to install at this time
                Write-Warning "$($c): Offline"
            }
        }
    }
}


<#
    
    .SYNOPSIS
        Gets information about the processes running in computer.
    
    .DESCRIPTION
        Gets information about the processes running in computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
    .COMPONENT
        ProcessList_Body

    .PARAMETER isLocal
        This parameter is MANDATORY.

        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-Processes -isLocal $True
    
#>
function Get-Processes {
    param
    (
        [Parameter(Mandatory = $true)]
        [boolean]
        $isLocal
    )
    
    Import-Module CimCmdlets -ErrorAction SilentlyContinue
    
    $processes = Get-CimInstance -Namespace root/Microsoft/Windows/ManagementTools -ClassName Msft_MTProcess
    
    $powershellProcessList = @{}
    $powerShellProcesses = Get-Process -ErrorAction SilentlyContinue
    
    foreach ($process in $powerShellProcesses) {
        $powershellProcessList.Add([int]$process.Id, $process)
    }
    
    if ($isLocal) {
        # critical processes taken from task manager code
        # https://microsoft.visualstudio.com/_git/os?path=%2Fbase%2Fdiagnosis%2Fpdui%2Fatm%2FApplications.cpp&version=GBofficial%2Frs_fun_flight&_a=contents&line=44&lineStyle=plain&lineEnd=59&lineStartColumn=1&lineEndColumn=3
        $criticalProcesses = (
            "$($env:windir)\system32\winlogon.exe",
            "$($env:windir)\system32\wininit.exe",
            "$($env:windir)\system32\csrss.exe",
            "$($env:windir)\system32\lsass.exe",
            "$($env:windir)\system32\smss.exe",
            "$($env:windir)\system32\services.exe",
            "$($env:windir)\system32\taskeng.exe",
            "$($env:windir)\system32\taskhost.exe",
            "$($env:windir)\system32\dwm.exe",
            "$($env:windir)\system32\conhost.exe",
            "$($env:windir)\system32\svchost.exe",
            "$($env:windir)\system32\sihost.exe",
            "$($env:ProgramFiles)\Windows Defender\msmpeng.exe",
            "$($env:ProgramFiles)\Windows Defender\nissrv.exe",
            "$($env:ProgramFiles)\Windows Defender\nissrv.exe",
            "$($env:windir)\explorer.exe"
        )
    
        $sidebarPath = "$($end:ProgramFiles)\Windows Sidebar\sidebar.exe"
        $appFrameHostPath = "$($env:windir)\system32\ApplicationFrameHost.exe"
    
        $edgeProcesses = (
            "$($env:windir)\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe",
            "$($env:windir)\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdgeCP.exe",
            "$($env:windir)\system32\browser_broker.exe"
        )
    
        foreach ($process in $processes) {
    
            if ($powershellProcessList.ContainsKey([int]$process.ProcessId)) {
                $psProcess = $powershellProcessList.Get_Item([int]$process.ProcessId)
                $hasChildWindow = $psProcess -ne $null -and $psProcess.MainWindowHandle -ne 0
                $process | Add-Member -MemberType NoteProperty -Name "HasChildWindow" -Value $hasChildWindow
                if ($psProcess.MainModule -and $psProcess.MainModule.FileVersionInfo) {
                    $process | Add-Member -MemberType NoteProperty -Name "FileDescription" -Value $psProcess.MainModule.FileVersionInfo.FileDescription
                }
            }
    
            if ($edgeProcesses -contains $nativeProcess.executablePath) {
                # special handling for microsoft edge used by task manager
                # group all edge processes into applications
                $edgeLabel = 'Microsoft Edge'
                if ($process.fileDescription) {
                    $process.fileDescription = $edgeLabel
                }
                else {
                    $process | Add-Member -MemberType NoteProperty -Name "FileDescription" -Value $edgeLabel
                }
    
                $processType = 'application'
            }
            elseif ($criticalProcesses -contains $nativeProcess.executablePath `
                    -or (($nativeProcess.executablePath -eq $null -or $nativeProcess.executablePath -eq '') -and $null -ne ($criticalProcesses | ? {$_ -match $nativeProcess.name})) ) {
                # process is windows if its executable path is a critical process, defined by Task Manager
                # if the process has no executable path recorded, fallback to use the name to match to critical process
                $processType = 'windows'
            }
            elseif (($nativeProcess.hasChildWindow -and $nativeProcess.executablePath -ne $appFrameHostPath) -or $nativeProcess.executablePath -eq $sidebarPath) {
                # sidebar.exe, or has child window (excluding ApplicationFrameHost.exe)
                $processType = 'application'
            }
            else {
                $processType = 'background'
            }
    
            $process | Add-Member -MemberType NoteProperty -Name "ProcessType" -Value $processType
        }
    }
    
    $processes
    
}


<#
    .SYNOPSIS
        This function starts a PowerShell Universal Dashboard (Web-based GUI) instance on the specified port on the
        localhost. The Dashboard features a Network Monitor tool that pings the specified Remote Hosts in your Domain
        every 5 seconds and reports the results to the site.

    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER Port
        This parameter is OPTIONAL, however, it has a default value of 80.

        This parameter takes an integer between 1 and 32768 that represents the port on the localhost that the site
        will run on.

    .PARAMETER InstallNmap
        This parameter is OPTIONAL, however, it has a default value of $True.

        This parameter is a switch. If used, nmap will be installed in order to guess the Operating System of
        Remote Hosts on the network.

    .PARAMETER RemoveExistingPUD
        This parameter is OPTIONAL, however, it has a default value of $True.

        This parameter is a switch. If used, all running PowerShell Universal Dashboard instances will be removed
        prior to starting the Network Monitor Dashboard.

    .PARAMETER LDAPCreds
        This parameter is OPTIONAL, however, if PUDAdminCenter is being run on Linux, it is MANDATORY.

        This parameter takes a pscredential that represents credentials with (at least) Read Access to your Domain's
        LDAP / Active Directory database.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-PUDAdminCenter
        
#>
function Get-PUDAdminCenter {
    Param (
        [Parameter(Mandatory=$False)]
        [ValidateRange(1,32768)]
        [int]$Port = 80,

        [Parameter(Mandatory=$False)]
        [switch]$InstallNmap = $False,

        [Parameter(Mandatory=$False)]
        [switch]$RemoveExistingPUD = $True,

        [Parameter(Mandatory=$False)]
        [pscredential]$LDAPCreds
    )

    #region >> Prep

    if ($PSVersionTable.Platform -eq "Unix" -and !$LDAPCreds) {
        Write-Error "Running PUDAdminCenter on Linux requires that you supply LDAP/Active Directory Credentials using the -LDAPCreds parameter! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Remove all current running instances of PUD
    if ($RemoveExistingPUD) {
        Get-UDDashboard | Stop-UDDashboard
    }

    # Remove All Runspaces to Remote Hosts
    Get-PSSession | Remove-PSSession
    $RunspacesToDispose = @(
        Get-Runspace | Where-Object {$_.Type -eq "Remote"}
    )
    if ($RunspacesToDispose.Count -gt 0) {
        foreach ($RSpace in $RunspacesToDispose) {$_.Dispose()}
    }

    # Define all of this Module's functions (both Public and Private) as an array of strings so that we can easily load them in different contexts/scopes
    $ThisModuleFunctionsStringArray =  $(Get-Module PUDAdminCenter).Invoke({$FunctionsForSBUse})

    # Create the $Pages ArrayList that will be used with 'New-UDDashboard -Pages'
    [System.Collections.ArrayList]$Pages = @()

    # Current Scope variable (ArrayList) containing the names of all of **Dynamic** Pages -
    # i.e. Pages where the URL contains a variable/parameter that is referenced within the Page itself.
    # For example, in this PUDAdminCenter App, the Overview Page (and all other Dynamic Pages in this list) is
    # eventually created via...
    #     New-UDPage -Url "/Overview/:RemoteHost" -Endpoint {param($RemoteHost) ...}
    # ...meaning that if a user were to navigate to http://localhost/Overview/Server01, Overview Page Endpoint scriptblock
    # code that referenced the variable $RemoteHost would contain the string value 'Server01' (unless it is specifcally
    # overriden within the Overview Page Endpoint scriptblock, which is NOT recommended).
    $DynamicPages = @(
        "PSRemotingCreds"
        "ToolSelect"
        "Overview"
        "Certificates"
        "Devices"
        "Events"
        "Files"
        "Firewall"
        "Users And Groups"
        "Network"
        "Processes"
        "Registry"
        "Roles And Features"
        "Scheduled Tasks"
        "Services"
        "Storage"
        "Updates"
    )

    if ($PSVersionTable.Platform -eq "Unix") {
        $RequiredLinuxCommands =  $(Get-Module PUDAdminCenter).Invoke({$RequiredLinuxCommands})
        [System.Collections.ArrayList]$CommandsNotPresent = @()
        foreach ($CommandName in $RequiredLinuxCommands) {
            $CommandCheckResult = command -v $CommandName
            if (!$CommandCheckResult) {
                $null = $CommandsNotPresent.Add($CommandName)
            }
        }

        if ($CommandsNotPresent.Count -gt 0) {
            [System.Collections.ArrayList]$FailedInstalls = @()
            if ($CommandsNotPresent -contains "echo" -or $CommandsNotPresent -contains "whoami") {
                try {
                    $null = InstallLinuxPackage -PossiblePackageNames "coreutils" -CommandName "echo"
                }
                catch {
                    $null = $FailedInstalls.Add("coreutils")
                }
            }
            if ($CommandsNotPresent -contains "nslookup" -or $CommandsNotPresent -contains "host" -or
            $CommandsNotPresent -contains "hostname" -or $CommandsNotPresent -contains "domainanme") {
                try {
                    $null = InstallLinuxPackage -PossiblePackageNames @("dnsutils","bindutils","bind-tools") -CommandName "nslookup"
                }
                catch {
                    $null = $FailedInstalls.Add("dnsutils_bindutils_bind-tools")
                }
            }
            if ($CommandsNotPresent -contains "ldapsearch") {
                try {
                    $null = InstallLinuxPackage -PossiblePackageNames "openldap-clients" -CommandName "ldapsearch"
                }
                catch {
                    $null = $FailedInstalls.Add("openldap-clients")
                }
            }
            if ($CommandsNotPresent -contains "expect") {
                try {
                    $null = InstallLinuxPackage -PossiblePackageNames "expect" -CommandName "expect"
                }
                catch {
                    $null = $FailedInstalls.Add("expect")
                }
            }
    
            if ($FailedInstalls.Count -gt 0) {
                Write-Error "The following Linux packages are required, but were not able to be installed:`n$($FailedInstalls -join "`n")`nHalting!"
                $global:FunctionResult = "1"
                return
            }
        }

        [System.Collections.ArrayList]$CommandsNotPresent = @()
        foreach ($CommandName in $RequiredLinuxCommands) {
            $CommandCheckResult = command -v $CommandName
            if (!$CommandCheckResult) {
                $null = $CommandsNotPresent.Add($CommandName)
            }
        }
    
        if ($CommandsNotPresent.Count -gt 0) {
            Write-Error "The following Linux commands are required, but not present on $env:ComputerName:`n$($CommandsNotPresent -join "`n")`nHalting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # Make sure we can resolve the $DomainName
    try {
        $DomainName = GetDomainName
        $ResolveDomainInfo = [System.Net.Dns]::Resolve($DomainName)
    }
    catch {
        Write-Error "Unable to resolve domain '$DomainName'! Halting!"
        $global:FunctionResult = "1"
        return
    }    

    # Create Synchronized Hashtable so that we can pass variables between Pages regardless of scope.
    # This provides benefits above and beyond Universal Dashboard's $Cache: scope for two main reasons:
    #     1) It can be referenced anywhere (not just within an -Endpoint, which is what $Cache: scope is limited to)
    #     2) It allows us to more easily communicate with our own custom Runspace(s) that handle Live (Realtime) Data. For
    #     examples of this, see uses of the 'New-Runspace' function within each of the Dynamic Pages (excluding the
    #     PSRemotingCreds and ToolSelect Pages)
    Remove-Variable -Name PUDRSSyncHT -Scope Global -Force -ErrorAction SilentlyContinue
    $global:PUDRSSyncHT = [hashtable]::Synchronized(@{})

    # Populate $PUDRSSyncHT with information that you will need for your PUD Application. This will vary depending on
    # how your application works, but at the very least, you should:
    #     1) Add a Key that will contain information that will be displayed on your HomePage (for the PUDAdminCenter App,
    #     this is the Value contained within the 'RemoteHostList' Key)
    #     2) If you are planning on using Live (Realtime) Data, ensure you add one or more keys that will contain
    #     Live Data. (For the PUDAdminCenter App, this is the LiveDataRSInfo Key that exists within a hashtable
    #     dedicated to each specific Remote Host)
    # For this PUDAdminCenter Application, the structure of the $PUDRSSyncHT will look like...
    <#
        @{
            RemoteHostList   = $null
            <RemoteHostInfo> = @{
                NetworkInfo                 = $null
                <DynamicPage>               = @{
                    <StaticInfoKey>     = $null
                    LiveDataRSInfo      = $null
                    LiveDataTracker     = @{
                        Current     = $null
                        Previous    = $null
                    }
                }
            }
        }
    #>
    # In other words. each Key within the $PUDRSSyncHT Synchronized Hashtable (with the exception of the 'RemoteHostList' key)
    # will represent a Remote Host that we intend to manage. Each RemoteHost key value will be a hashtable containing the key
    # 'NetworkInfo', as well as keys that rperesent relevant Dynamic Pages ('Overview','Certificates',etc). Each Dynamic Page
    # key value will be a hashtable containing one or more keys with value(s) representing static info that is queried at the time
    # the page loads as well as the keys 'LiveDataRSInfo', and 'LiveDataTracker'. Some key values are initially set to $null because
    # actions taken either prior to starting the UDDashboard or actions taken within the PUDAdminCenter WebApp itself on different
    # pages will set/reset their values as appropriate.

    # Let's populate $PUDRSSyncHT.RemoteHostList with information that will be needed immediately upon navigating to the $HomePage.
    # For this reason, we're gathering the info before we start the UDDashboard. (Note that the below 'GetComputerObjectInLDAP' Private
    # function gets all Computers in Active Directory without using the ActiveDirectory PowerShell Module)
    if ($PSVersionTable.Platform -eq "Unix") {
        [System.Collections.ArrayList]$InitialRemoteHostListPrep = GetComputerObjectsInLDAP -ObjectCount 20 -LDAPCreds $LDAPCreds
        $PUDRSSyncHT.Add("LDAPCreds",$LDAPCreds)
    }
    else {
        [System.Collections.ArrayList]$InitialRemoteHostListPrep = $(GetComputerObjectsInLDAP -ObjectCount 20).Name
    }
    # Let's just get 20 of them initially. We want *something* on the HomePage but we don't want hundreds/thousands of entries. We want
    # the user to specify individual/range of hosts/devices that they want to manage.
    #$InitialRemoteHostListPrep = $InitialRemoteHostListPrep[0..20]
    if ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Win32NT") {
        [System.Collections.ArrayList]$InitialRemoteHostListPrep = $InitialRemoteHostListPrep | foreach {$_ -replace "CN=",""}
    }
    if ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Unix") {
        [System.Collections.ArrayList]$InitialRemoteHostListPrep = $InitialRemoteHostListPrep | foreach {$($_ -replace "cn: ","").Trim()}
    }

    # Filter Out the Remote Hosts that we can't resolve
    [System.Collections.ArrayList]$InitialRemoteHostList = @()

    # NOTE: Not having the Platform Property necessarily means we're on Windows PowerShell
    if ($PSVersionTable.Platform -eq "Win32NT" -or !$PSVersionTable.Platform) {
        if ($PSVersionTable.PSEdition -eq "Core") {
            Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                $null = Clear-DnsClientCache
            }
        }
        else {
            $null = Clear-DnsClientCache
        }
    }
    else {
        Write-Verbose "Flushing the DNS Client Cache is generally not needed on Linux since the default (for most distros) is not to cache anything."
    }
    
    foreach ($HName in $InitialRemoteHostListPrep) {
        try {
            $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $HName -ErrorAction Stop

            if ($RemoteHostNetworkInfo.HostName -eq "localhost") {
                $HostNameOutput = hostname
                $HostNameShort = if ($HostNameOutput -match "\.") {$($HostNameOutput -split "\.")[0]} else {$HostNameOutput}
                [System.Collections.ArrayList][array]$IPAddresses = Get-NetworkInfo -InterfaceStatus Up -AddressFamily IPv4 | foreach {$_.Address.IPAddressToString}

                $RemoteHostNetworkInfo.FQDN = $HostNameOutput
                $RemoteHostNetworkInfo.HostName = $HostNameShort
                $RemoteHostNetworkInfo.IPAddressList = $IPAddresses
                $RemoteHostNetworkInfo.Domain = GetDomainName
            }

            # ResolveHost will NOT throw an error even if it can't figure out HostName, Domain, or FQDN as long as $IPAddr IS pingable
            # So, we need to do the below to compensate for code downstream that relies on HostName, Domain, and FQDN
            if (!$RemoteHostNetworkInfo.HostName) {
                $IPAddr = $RemoteHostNetworkInfo.IPAddressList[0]
                $LastTwoOctets = $($IPAddr -split '\.')[2..3] -join 'Dot'
                $UpdatedHostName = NewUniqueString -PossibleNewUniqueString "Unknown$LastTwoOctets" -ArrayOfStrings $PUDRSSyncHT.RemoteHostList.HostName
                $RemoteHostNetworkInfo.HostName = $UpdatedHostName
                $RemoteHostNetworkInfo.FQDN = $UpdatedHostName + '.Unknown'
                $RemoteHostNetworkInfo.Domain = 'Unknown'
            }

            if ($InitialRemoteHostList.FQDN -notcontains $RemoteHostNetworkInfo.FQDN) {
                $null = $InitialRemoteHostList.Add($RemoteHostNetworkInfo)
            }
        }
        catch {
            continue
        }
    }

    $PUDRSSyncHT.Add("RemoteHostList",$InitialRemoteHostList)

    # Add Keys for each of the Remote Hosts in the $InitialRemoteHostList    
    foreach ($RHost in $InitialRemoteHostList) {
        $Key = $RHost.HostName + "Info"
        $Value = @{
            NetworkInfo                 = $RHost
            CredHT                      = $null
            ServerInventoryStatic       = $null
            RelevantNetworkInterfaces   = $null
            LiveDataRSInfo              = $null
            LiveDataTracker             = @{Current = $null; Previous = $null}
        }
        foreach ($DynPage in $($DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
            $DynPageHT = @{
                LiveDataRSInfo      = $null
                LiveDataTracker     = @{Current = $null; Previous = $null}
            }
            $Value.Add($($DynPage -replace "[\s]",""),$DynPageHT)
        }
        $PUDRSSyncHT.Add($Key,$Value)
    }

    if ($InstallNmap) {
        # Install nmap
        if ($(Get-Module -ListAvailable).Name -notcontains "ProgramManagement") {Install-Module ProgramManagement}
        if ($(Get-Module).Name -notcontains "ProgramManagement") {Import-Module ProgramManagement}
        if (!$(Get-Command nmap -ErrorAction SilentlyContinue)) {
            try {
                Write-Host "Installing 'nmap'. This could take up to 10 minutes..." -ForegroundColor Yellow
                $InstallnmapResult = Install-Program -ProgramName nmap -CommandName nmap
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        if (!$(Get-Command nmap -ErrorAction SilentlyContinue)) {
            Write-Error "Unable to find the command 'nmap'! Halting!"
            $global:FunctionResult = "1"
            return
        }
        $NmapParentDir = $(Get-Command nmap).Source | Split-Path -Parent
        [System.Collections.Arraylist][array]$CurrentEnvPathArray = $env:Path -split ';' | Where-Object {![System.String]::IsNullOrWhiteSpace($_)}
        if ($CurrentEnvPathArray -notcontains $NmapParentDir) {
            $CurrentEnvPathArray.Insert(0,$NmapParentDir)
            $env:Path = $CurrentEnvPathArray -join ';'
        }
        $SystemPathInRegistry = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment'
        $CurrentSystemPath = $(Get-ItemProperty -Path $SystemPathInRegistry -Name PATH).Path
        [System.Collections.Arraylist][array]$CurrentSystemPathArray = $CurrentSystemPath -split ";" | Where-Object {![System.String]::IsNullOrWhiteSpace($_)}
        if ($CurrentSystemPathArray -notcontains $NmapParentDir) {
            $CurrentSystemPathArray.Insert(0,$NmapParentDir)
            $UpdatedSystemPath = $CurrentSystemPathArray -join ';'
            Set-ItemProperty -Path $SystemPathInRegistry -Name PATH -Value $UpdatedSystemPath
        }
    }

    #endregion >> Prep


    #region >> Dynamic Pages

    #region >> Disconnected Page
    
    $DisconnectedPageContent = {
        param($RemoteHost)
    
        # Add the SyncHash to the Page so that we can pass output to other pages
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        $ConnectionStatusTableProperties = @("RemoteHost", "Status")
    
        New-UDRow -Columns {
            New-UDColumn -Size 4 -Content {
                New-UDHeading -Text ""
            }
            New-UDColumn -Size 4 -Content {
                New-UDTable -Headers $ConnectionStatusTableProperties -AutoRefresh -Endpoint {
                    [PSCustomObject]@{
                        RemoteHost      = $RemoteHost.ToUpper()
                        Status          = "Disconnected"
                    } | Out-UDTableData -Property @("RemoteHost", "Status")
                }
            }
            New-UDColumn -Size 4 -Content {
                New-UDHeading -Text ""
            }
        }
    
        New-UDRow -Columns {
            New-UDColumn -Size 5 -Content {
                New-UDHeading -Text ""
            }
            New-UDColumn -Size 2 -Content {
                New-UDLink -Text "|| Return Home ||" -Url "/Home"
            }
            New-UDColumn -Size 5 -Content {
                New-UDHeading -Text ""
            }
        }
    
        New-UDRow -Columns {
            New-UDColumn -Size 12 -Content {
                # Grid below UDTable
                $ResultProperties = @("HostName","FQDN","IPAddress","PingStatus","WSMan","WSManPorts","SSH","DateTime","ManageLink")
    
                $RHost = $PUDRSSyncHT."$RemoteHost`Info".NetworkInfo
    
                $GridEndpoint = {
                    $GridData = @{}
                    $GridData.Add("HostName",$RHost.HostName.ToUpper())
                    $GridData.Add("FQDN",$RHost.FQDN)
                    $GridData.Add("IPAddress",$RHost.IPAddressList[0])
    
                    # Check Ping
                    try {
                        $PingResult =  [System.Net.NetworkInformation.Ping]::new().Send(
                            $RHost.IPAddressList[0],1000
                        ) | Select-Object -Property Address,Status,RoundtripTime -ExcludeProperty PSComputerName,PSShowComputerName,RunspaceId
    
                        $PingStatus = if ($PingResult.Status.ToString() -eq "Success") {"Available"} else {"Unavailable"}
                        $GridData.Add("PingStatus",$PingStatus)
                    }
                    catch {
                        $GridData.Add("PingStatus","Unavailable")
                    }
    
                    # Check WSMan Ports
                    try {
                        $WSMan5985Url = "http://$($RHost.IPAddressList[0])`:5985/wsman"
                        $WSMan5986Url = "http://$($RHost.IPAddressList[0])`:5986/wsman"
                        $WSManUrls = @($WSMan5985Url,$WSMan5986Url)
                        foreach ($WSManUrl in $WSManUrls) {
                            $Request = [System.Net.WebRequest]::Create($WSManUrl)
                            $Request.Timeout = 1000
                            try {
                                [System.Net.WebResponse]$Response = $Request.GetResponse()
                            }
                            catch {
                                if ($_.Exception.Message -match "The remote server returned an error: \(405\) Method Not Allowed") {
                                    if ($WSManUrl -match "5985") {
                                        $WSMan5985Available = $True
                                    }
                                    else {
                                        $WSMan5986Available = $True
                                    }
                                }
                                elseif ($_.Exception.Message -match "The operation has timed out") {
                                    if ($WSManUrl -match "5985") {
                                        $WSMan5985Available = $False
                                    }
                                    else {
                                        $WSMan5986Available = $False
                                    }
                                }
                                else {
                                    if ($WSManUrl -match "5985") {
                                        $WSMan5985Available = $False
                                    }
                                    else {
                                        $WSMan5986Available = $False
                                    }
                                }
                            }
                        }
    
                        if ($WSMan5985Available -or $WSMan5986Available) {
                            $GridData.Add("WSMan","Available")
    
                            [System.Collections.ArrayList]$WSManPorts = @()
                            if ($WSMan5985Available) {
                                $null = $WSManPorts.Add("5985")
                            }
                            if ($WSMan5986Available) {
                                $null = $WSManPorts.Add("5986")
                            }
    
                            $WSManPortsString = $WSManPorts -join ', '
                            $GridData.Add("WSManPorts",$WSManPortsString)
                        }
                    }
                    catch {
                        $GridData.Add("WSMan","Unavailable")
                    }
    
                    # Check SSH
                    try {
                        $TestSSHResult = TestPort -HostName $RHost.IPAddressList[0] -Port 22
    
                        if ($TestSSHResult.Open) {
                            $GridData.Add("SSH","Available")
                        }
                        else {
                            $GridData.Add("SSH","Unavailable")
                        }
                    }
                    catch {
                        $GridData.Add("SSH","Unavailable")
                    }
    
                    $GridData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                    if ($GridData.WSMan -eq "Available" -or $GridData.SSH -eq "Available") {
                        if ($PUDRSSyncHT."$($RHost.HostName)`Info".PSRemotingCreds -ne $null) {
                            $GridData.Add("ManageLink",$(New-UDLink -Text "Manage" -Url "/ToolSelect/$($RHost.HostName)"))
                        }
                        else {
                            $GridData.Add("ManageLink",$(New-UDLink -Text "Manage" -Url "/PSRemotingCreds/$($RHost.HostName)"))
                        }
                    }
                    else {
                        $GridData.Add("ManageLink","Unavailable")
                    }
                    
                    [pscustomobject]$GridData | Out-UDGridData
                }
    
                $NewUdGridSplatParams = @{
                    Headers         = $ResultProperties 
                    NoPaging        = $True
                    Properties      = $ResultProperties
                    AutoRefresh     = $True
                    RefreshInterval = 5
                    Endpoint        = $GridEndpoint
                }
                New-UdGrid @NewUdGridSplatParams
            }
        }
    }
    $Page = New-UDPage -Url "/Disconnected/:RemoteHost" -Endpoint $DisconnectedPageContent
    $null = $Pages.Add($Page)
    # We need this page as a string for later on. For some reason, we can't use this same ScriptBlock directly on other Pages
    $DisconnectedPageContentString = $DisconnectedPageContent.ToString()
    
    #endregion >> Disconnected Page
    
    #region >> PSRemoting Creds Page
    
    $PSRemotingCredsPageContent = {
        param($RemoteHost)
    
        New-UDColumn -Endpoint {$Session:ThisRemoteHost = $RemoteHost}
    
        # Add the SyncHash to the Page so that we can pass output to other pages
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:PSRemotingPageLoadingTracker = [System.Collections.ArrayList]::new()
                #$PUDRSSyncHT.PSRemotingPageLoadingTracker = $Session:HomePageLoadingTracker
                $Session:NoCredsEntered = $False
                $Session:InvalidSSHPubCert = $False
                $Session:SSHRemotingMethodNoCert = $False
                $Session:DomainRemotingMethodNoCreds = $False
                $Session:LocalRemotingMethodNoCreds = $False
                $Session:UserNameAndPasswordRequired = $False
                $Session:BadFormatDomainUserName = $False
                $Session:EnableWinRMFailure = $False
                $Session:GetWorkingCredsFailure = $False
                $Session:InvalidCreds = $False
                $Session:CheckingCredentials = $False
            }
            New-UDHeading -Text "Set Credentials for $($RemoteHost.ToUpper())" -Size 4
        }
    
        New-UDRow -Columns {
            New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                if ($Session:PSRemotingPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
    
            New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                New-UDElement -Id "CheckingCredentials" -Tag div -EndPoint {
                    if ($Session:CheckingCredentials) {
                        New-UDHeading -Text "Checking Credentials for $Session:ThisRemoteHost...Please wait..." -Size 5
                        New-UDPreloader -Size small
                    }
                }
            }
    
            New-UDColumn -EndPoint {
                New-UDElement -Id "ValidateCredsMsg" -Tag div -EndPoint {
                    #New-UDHeading -Text "RemoteHost is $Session:ThisRemoteHost!" -Size 6 -Color red
    
                    if ($Session:NoCredsEntered) {
                        New-UDHeading -Text "You MUST enter UserName/Password for either a Local User or Domain User with access to $Session:ThisRemoteHost!" -Size 6 -Color red
                        $Session:NoCredsEntered = $False
                    }
                    if ($Session:InvalidSSHPubCert) {
                        New-UDHeading -Text "The string provided is not a valid SSH Public Certificate!" -Size 6 -Color red
                        $Session:InvalidSSHPubCert = $False
                    }
                    if ($Session:SSHRemotingMethodNoCert) {
                        New-UDHeading -Text "You indicated that SSH is your Preferred_PSRemotingMethod, however, you did not provide a value for Path_To_SSH_Public_Cert!" -Size 6 -Color red
                        $Session:SSHRemotingMethodNoCert = $False
                    }
                    if ($Session:DomainRemotingMethodNoCreds) {
                        New-UDHeading -Text "You indicated that 'Domain' was your Preferred_PSRemotingCredType, however, you did not provide Domain Credentials!" -Size 6 -Color red
                        $Session:DomainRemotingMethodNoCreds = $False
                    }
                    if ($Session:LocalRemotingMethodNoCreds) {
                        New-UDHeading -Text "You indicated that 'Local' was your Preferred_PSRemotingCredType, however, you did not provide Local Credentials!" -Size 6 -Color red
                        $Session:LocalRemotingMethodNoCreds = $False
                    }
                    if ($Session:UserNameAndPasswordRequired) {
                        New-UDHeading -Text "Please enter both a UserName and a Password!" -Size 6 -Color red
                        $Session:UserNameAndPasswordRequired = $False
                    }
                    if ($Session:BadFormatDomainUserName) {
                        New-UDHeading -Text "Domain_UserName must be in format 'Domain\DomainUser'!" -Size 6 -Color red
                        $Session:BadFormatDomainUserName = $False
                    }
                    if ($Session:EnableWinRMFailure) {
                        New-UDHeading -Text "Unable to Enable WinRM on $Session:ThisRemoteHost via Invoke-WmiMethod over RPC! Please check your credentials." -Size 6 -Color red
                        $Session:EnableWinRMFailure = $False
                    }
                    if ($Session:GetWorkingCredsFailure) {
                        New-UDHeading -Text "Unable to test Credentials! Please try again." -Size 6 -Color red
                        $Session:GetWorkingCredsFailure = $False
                    }
                    if ($Session:InvalidCreds) {
                        New-UDHeading -Text "Invalud Credentials! Please try again." -Size 6 -Color red
                        $Session:InvalidCreds = $False
                    }
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        <#
        New-UDRow -Endpoint {
            New-UDColumn -Size 2 -Content {}
            New-UDColumn -Size 8 -Endpoint {
                New-UDRow -Endpoint {
                    New-UDTextbox -Id "LocalUserName" -Label "Local UserName" -Type text
                    New-UDTextbox -Id "LocalPassword" -Label "Local Password" -Type password
                    New-UDTextbox -Id "DomainUserName" -Label "Domain UserName" -Type text
                    New-UDTextbox -Id "DomainPassword" -Label "Domain Password" -Type password
                    New-UDTextbox -Id "SSHPublicCert" -Label "SSH Public Certificate" -Type text
                    New-UDSelect -Id "PreferredPSRemotingCredType" -Label "Credential Type" -Option {
                        New-UDSelectOption -Name "Domain" -Value "Domain" -Selected
                        New-UDSelectOption -Name "Local" -Value "Local"
                    }
                    New-UDSelect -Id "PreferredPSRemotingMethod" -Label "PSRemoting Method" -Option {
                        New-UDSelectOption -Name "WinRM" -Value "WinRM" -Selected
                        New-UDSelectOption -Name "SSH" -Value "SSH"
                    }
                }
                New-UDRow -EndPoint {
                    New-UDButton -Text "Set Credentials" -OnClick {
                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                        $Session:CheckingCredentials = $True
                        Sync-UDElement -Id "CheckingCredentials"
    
                        $LocalUserNameTextBox = Get-UDElement -Id "LocalUserName"
                        $LocalPasswordTextBox = Get-UDElement -Id "LocalPassword"
                        $DomainUserNameTextBox = Get-UDElement -Id "DomainUserName"
                        $DomainPasswordTextBox = Get-UDElement -Id "DomainPassword"
                        $SSHPublicCertTextBox = Get-UDElement -Id "SSHPublicCert"
                        $PrefCredTypeSelection = Get-UDElement -Id "PreferredPSRemotingCredType"
                        $PrefRemotingMethodSelection = Get-UDElement -Id "PreferredPSRemotingMethod"
                        
                        $Local_UserName = $LocalUserNameTextBox.Attributes['value']
                        $Local_Password = $LocalPasswordTextBox.Attributes['value']
                        $Domain_UserName = $DomainUserNameTextBox.Attributes['value']
                        $Domain_Password = $DomainPasswordTextBox.Attributes['value']
                        $VaultServerUrl = $SSHPublicCertTextBox.Attributes['value']
                        $Preferred_PSRemotingCredType = $($PrefCredTypeSelection.Content | foreach {
                            $_.ToString() | ConvertFrom-Json
                        } | Where-Object {$_.attributes.selected.isPresent}).attributes.value
                        $Preferred_PSRemotingMethod = $($PrefRemotingMethodSelection.Content | foreach {
                            $_.ToString() | ConvertFrom-Json
                        } | Where-Object {$_.attributes.selected.isPresent}).attributes.value
    
                        $TestingCredsObj = [pscustomobject]@{
                            LocalUserNameTextBox            = $LocalUserNameTextBox
                            LocalPasswordTextBox            = $LocalPasswordTextBox
                            DomainUserNameTextBox           = $DomainUserNameTextBox
                            DomainPasswordTextBox           = $DomainPasswordTextBox
                            SSHPublicCertTextBox            = $SSHPublicCertTextBox
                            PrefCredTypeSelection           = $PrefCredTypeSelection
                            PrefRemotingMethodSelection     = $PrefRemotingMethodSelection
                            Local_UserName                  = $Local_UserName
                            Local_Password                  = $Local_Password
                            Domain_UserName                 = $Domain_UserName
                            Domain_Password                 = $Domain_Password
                            VaultServerUrl             = $VaultServerUrl
                            Preferred_PSRemotingCredType    = $Preferred_PSRemotingCredType
                            Preferred_PSRemotingMethod      = $Preferred_PSRemotingMethod
                            RemoteHost                      = $Session:ThisRemoteHost
                        }
    
                        if ($Session:CredentialHT.Keys -notcontains $Session:ThisRemoteHost) {
                            #New-UDInputAction -Toast "`$Session:CredentialHT is not defined!" -Duration 10000
                            $Session:CredentialHT = @{}
                            $RHostCredHT = @{
                                DomainCreds         = $null
                                LocalCreds          = $null
                                VaultServerUrl      = $null
                                PSRemotingCredType  = $null
                                PSRemotingMethod    = $null
                                PSRemotingCreds     = $null
                            }
                            $Session:CredentialHT.Add($Session:ThisRemoteHost,$RHostCredHT)
    
                            # TODO: Need to remove this when finished testing
                            $PUDRSSyncHT."$Session:ThisRemoteHost`Info".CredHT = $Session:CredentialHT
    
                            #New-UDInputAction -Toast "`$Session:CredentialHT was null" -Duration 10000
                        }
    
                        # In case this page was refreshed or redirected to from itself, check $Session:CredentialHT for existing values
                        if (!$Local_UserName -and $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds -ne $null) {
                            $Local_UserName = $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds.UserName
                        }
                        if (!$Local_Password -and $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds -ne $null) {
                            $Local_Password = $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds.GetNetworkCredential().Password
                        }
                        if (!$Domain_UserName -and $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds -ne $null) {
                            $Domain_UserName = $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds.UserName
                        }
                        if (!$Domain_Password -and $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds -ne $null) {
                            $Domain_Password = $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds.GetNetworkCredential().Password
                        }
                        if (!$VaultServerUrl -and $Session:CredentialHT.$Session:ThisRemoteHost.VaultServerUrl -ne $null) {
                            $VaultServerUrl = $Session:CredentialHT.$Session:ThisRemoteHost.VaultServerUrl
                        }
                        if (!$Preferred_PSRemotingCredType -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType -ne $null) {
                            $Preferred_PSRemotingCredType = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType
                        }
                        if (!$Preferred_PSRemotingMethod -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod -ne $null) {
                            $Preferred_PSRemotingMethod = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod
                        }
    
                        if (!$Local_UserName -and !$Local_Password -and !$Domain_UserName -and !$Domain_Password -and !$VaultServerUrl) {
                            $Session:NoCredsEntered = $True
                            Sync-UDElement -Id "ValidateCredsMsg"
                            $Session:CheckingCredentials = $False
                            Sync-UDElement -Id "CheckingCredentials"
                            return
                        }
    
                        if ($VaultServerUrl) {
                            # TODO: Validate the provided string is a SSH Public Cert
                            if ($BadSSHPubCert) {
                                $Session:InvalidSSHPubCert = $True
                                Sync-UDElement -Id "ValidateCredsMsg"
                                $Session:CheckingCredentials = $False
                                Sync-UDElement -Id "CheckingCredentials"
                                return
                            }
                        }
    
                        if (!$Preferred_PSRemotingMethod -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod) {
                            $Preferred_PSRemotingMethod = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod
                        }
                        if ($Preferred_PSRemotingMethod -eq "SSH" -and !$VaultServerUrl) {
                            $Session:SSHRemotingMethodNoCert = $True
                            Sync-UDElement -Id "ValidateCredsMsg"
                            $Session:CheckingCredentials = $False
                            Sync-UDElement -Id "CheckingCredentials"
                            return
                        }
    
                        if (!$Preferred_PSRemotingCredType -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType) {
                            $Preferred_PSRemotingCredType = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType
                        }
                        if ($Preferred_PSRemotingCredType -eq "Domain" -and $(!$Domain_UserName -or !$Domain_Password)) {
                            $Session:DomainRemotingMethodNoCreds = $True
                            Sync-UDElement -Id "ValidateCredsMsg"
                            $Session:CheckingCredentials = $False
                            Sync-UDElement -Id "CheckingCredentials"
                            return
                        }
    
                        if ($Preferred_PSRemotingCredType -eq "Local" -and $(!$Local_UserName -or !$Local_Password)) {
                            $Session:LocalRemotingMethodNoCreds = $True
                            Sync-UDElement -Id "ValidateCredsMsg"
                            $Session:CheckingCredentials = $False
                            Sync-UDElement -Id "CheckingCredentials"
                            return
                        }
    
                        if ($($Local_UserName -and !$Local_Password) -or $(!$Local_UserName -and $Local_Password) -or
                        $($Domain_UserName -and !$Domain_Password) -or $(!$Domain_UserName -and $Domain_Password)
                        ) {
                            $Session:UserNameAndPasswordRequired = $True
                            Sync-UDElement -Id "ValidateCredsMsg"
                            $Session:CheckingCredentials = $False
                            Sync-UDElement -Id "CheckingCredentials"
                            return
                        }
    
                        if ($Local_UserName -and $Local_Password) {
                            # Make sure the $Local_UserName is in format $Session:ThisRemoteHost\$Local_UserName
                            if ($Local_UserName -notmatch "^$Session:ThisRemoteHost\\[a-zA-Z0-9]+$") {
                                $Local_UserName = "$Session:ThisRemoteHost\$Local_UserName"
                            }
    
                            $LocalPwdSecureString = ConvertTo-SecureString $Local_Password -AsPlainText -Force
                            $LocalAdminCreds = [pscredential]::new($Local_UserName,$LocalPwdSecureString)
                        }
    
                        if ($Domain_UserName -and $Domain_Password) {
                            $DomainShortName = $($PUDRSSyncHT."$Session:ThisRemoteHost`Info".NetworkInfo.Domain -split "\.")[0]
                            # Make sure the $Domain_UserName is in format $Session:ThisRemoteHost\$Domain_UserName
                            if ($Domain_UserName -notmatch "^$DomainShortName\\[a-zA-Z0-9]+$") {
                                $Session:BadFormatDomainUserName = $True
                                Sync-UDElement -Id "ValidateCredsMsg"
                                $Session:CheckingCredentials = $False
                                Sync-UDElement -Id "CheckingCredentials"
                                return
                            }
    
                            $DomainPwdSecureString = ConvertTo-SecureString $Domain_Password -AsPlainText -Force
                            $DomainAdminCreds = [pscredential]::new($Domain_UserName,$DomainPwdSecureString)
                        }
    
                        # Test the Credentials
                        [System.Collections.ArrayList]$CredentialsToTest = @()
                        if ($LocalAdminCreds) {
                            $PSObj = [pscustomobject]@{CredType = "LocalUser"; PSCredential = $LocalAdminCreds}
                            $null = $CredentialsToTest.Add($PSObj)
                        }
                        if ($DomainAdminCreds) {
                            $PSObj = [pscustomobject]@{CredType = "DomainUser"; PSCredential = $DomainAdminCreds}
                            $null = $CredentialsToTest.Add($PSObj)
                        }
    
                        [System.Collections.ArrayList]$FailedCredentialsA = @()
                        foreach ($CredObj in $CredentialsToTest) {
                            try {
                                $GetWorkingCredsResult = GetWorkingCredentials -RemoteHostNameOrIP $Session:ThisRemoteHost -AltCredentials $CredObj.PSCredential -ErrorAction Stop
                
                                if ($GetWorkingCredsResult.DeterminedCredsThatWorkedOnRemoteHost) {
                                    if ($GetWorkingCredsResult.WorkingCredentials.GetType().FullName -ne "System.Management.Automation.PSCredential") {
                                        $null = $FailedCredentialsA.Add($CredObj)
                                    }
                                }
                                else {
                                    $null = $FailedCredentialsA.Add($CredObj)
                                }
                            }
                            catch {}
                        }
    
                        if ($($CredentialsToTest.Count -eq 2 -and $FailedCredentialsA.Count -eq 2) -or 
                        $($CredentialsToTest.Count -eq 1 -and $FailedCredentialsA.Count -eq 1)
                        ) {
                            # Since WinRM failed, try and enable WinRM Remotely via Invoke-WmiMethod over RPC Port 135 (if it's open)
                            $RPCPortOpen = $(TestPort -HostName $Session:ThisRemoteHost -Port 135).Open
    
                            [System.Collections.ArrayList]$EnableWinRMSuccess = @()
                            foreach ($CredObj in $CredentialsToTest) {
                                if ($RPCPortOpen) {
                                    try {
                                        $null = EnableWinRMViaRPC -RemoteHostNameOrIP $Session:ThisRemoteHost -Credential $CredObj.PSCredential
                                        $null = $EnableWinRMSuccess.Add($CredObj)
                                        break
                                    }
                                    catch {
                                        #New-UDInputAction -Toast "Failed to enable WinRM Remotely using Credentials $($CredObj.PSCredential.UserName)" -Duration 10000
                                    }
                                }
                            }
    
                            if ($EnableWinRMSuccess.Count -eq 0) {
                                $Session:EnableWinRMFailure = $True
                                Sync-UDElement -Id "ValidateCredsMsg"
                                $Session:CheckingCredentials = $False
                                Sync-UDElement -Id "CheckingCredentials"
                                return
                            }
                            else {
                                [System.Collections.ArrayList]$FailedCredentialsB = @()
                                foreach ($CredObj in $CredentialsToTest) {
                                    try {
                                        $GetWorkingCredsResult = GetWorkingCredentials -RemoteHostNameOrIP $Session:ThisRemoteHost -AltCredentials $CredObj.PSCredential -ErrorAction Stop
                        
                                        if ($GetWorkingCredsResult.WorkingCredentials.GetType().FullName -ne "System.Management.Automation.PSCredential") {
                                            #New-UDInputAction -Toast "$($CredObj.CredType) Credentials are not valid! Please try again." -Duration 10000
                                            $null = $FailedCredentialsB.Add($CredObj)
                                        }
                                    }
                                    catch {
                                        $Session:GetWorkingCredsFailure = $True
                                        Sync-UDElement -Id "ValidateCredsMsg"
                                        $Session:CheckingCredentials = $False
                                        Sync-UDElement -Id "CheckingCredentials"
                                        return
                                        
                                        #Show-UDToast -Message $_.Exception.Message -Duration 10
                                    }
                                }
                            }
                        }
    
                        if ($FailedCredentialsA.Count -gt 0 -or $FailedCredentialsB.Count -gt 0) {
                            if ($FailedCredentialsB.Count -gt 0) {
                                foreach ($CredObj in $FailedCredentialsB) {
                                    $Session:GetWorkingCredsFailure = $True
                                    Sync-UDElement -Id "ValidateCredsMsg"
                                    #$Session:CredentialHT.$Session:ThisRemoteHost."$CredType`Creds" = $null
                                }
                                $Session:CheckingCredentials = $False
                                Sync-UDElement -Id "CheckingCredentials"
                                return
                            }
                            if ($FailedCredentialsA.Count -gt 0 -and $FailedCredentialsB.Count -eq 0) {
                                foreach ($CredObj in $FailedCredentialsA) {
                                    $Session:GetWorkingCredsFailure = $True
                                    Sync-UDElement -Id "ValidateCredsMsg"
                                }
                                $Session:CheckingCredentials = $False
                                Sync-UDElement -Id "CheckingCredentials"
                                return
                            }
                        }
    
                        if ($DomainAdminCreds) {
                            $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds = $DomainAdminCreds
                        }
                        if ($LocalAdminCreds) {
                            $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds = $LocalAdminCreds
                        }
                        if ($VaultServerUrl) {
                            $Session:CredentialHT.$Session:ThisRemoteHost.VaultServerUrl = $VaultServerUrl
                        }
                        if ($Preferred_PSRemotingCredType) {
                            $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType = $Preferred_PSRemotingCredType
                        }
                        if ($Preferred_PSRemotingMethod) {
                            $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod = $Preferred_PSRemotingMethod
                        }
    
                        # Determine $PSRemotingCreds
                        if ($Preferred_PSRemotingCredType -eq "Local") {
                            $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds = $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds
                        }
                        if ($Preferred_PSRemotingCredType -eq "Domain") {
                            $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds = $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds
                        }
    
                        Invoke-UDRedirect -Url "/ToolSelect/$Session:ThisRemoteHost"
                    }
                }
                New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                    try {
                        $null = $Session:PSRemotingPageLoadingTracker.Add("FinishedLoading")
                    }
                    catch {
                        Write-Verbose "`$Session:PSRemotingPageLoadingTracker hasn't been set yet..."
                    }
                }
            }
            New-UDColumn -Size 2 -Content {}
        }
        #>
    
        New-UDRow -Endpoint {
            New-UDColumn -Size 2 -EndPoint {}
            New-UDColumn -Size 8 -EndPoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:CredsForm = New-UDInput -SubmitText "Set Credentials" -Id "CredsForm" -Content {
                    New-UDInputField -Type textbox -Name 'Local_UserName' -Value $null
                    New-UDInputField -Type password -Name 'Local_Password' -Value $null
                    New-UDInputField -Type textbox -Name 'Domain_UserName' -Value $null
                    New-UDInputField -Type password -Name 'Domain_Password' -Value $null
                    New-UDInputField -Type textbox -Name 'VaultServerUrl' -Value $null
                    New-UDInputField -Type select -Name 'Preferred_PSRemotingCredType' -Values @("Local","Domain","SSHCertificate") -DefaultValue "Domain"
    
                    [System.Collections.ArrayList]$PSRemotingMethodValues = @()
                    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
                        $null = $PSRemotingMethodValues.Add("WinRM")
                        $DefaultValue = "WinRM"
                    }
                    if ($PUDRSSyncHT."$Session:ThisRemoteHost`Info".RHostTableData.SSH -eq "Available" -or $PSVersionTable.Platform -eq "Unix") {
                        $null = $PSRemotingMethodValues.Add("SSH")
                        $DefaultValue = "SSH"
                    }
                    New-UDInputField -Type select -Name 'Preferred_PSRemotingMethod' -Values $PSRemotingMethodValues -DefaultValue $DefaultValue
                } -Endpoint {
                    param(
                        [string]$Local_UserName,
                        [string]$Local_Password,
                        [string]$Domain_UserName,
                        [string]$Domain_Password,
                        [string]$VaultServerUrl,
                        [string]$Preferred_PSRemotingCredType,
                        [string]$Preferred_PSRemotingMethod
                    )
    
                    # Add the SyncHash to the Page so that we can pass output to other pages
                    $PUDRSSyncHT = $global:PUDRSSyncHT
    
                    # Load PUDAdminCenter Module Functions Within ScriptBlock
                    $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                    try {
                        if ($Session:CredentialHT.GetType().FullName -ne "System.Collections.Hashtable") {
                            $Session:CredentialHT = @{}
                        }
                    }
                    catch {
                        $Session:CredentialHT = @{}
                    }
    
                    if ($Session:CredentialHT.Keys -notcontains $Session:ThisRemoteHost) {
                        $RHostCredHT = @{
                            DomainCreds         = $null
                            LocalCreds          = $null
                            VaultServerUrl      = $null
                            PSRemotingCredType  = $null
                            PSRemotingMethod    = $null
                            PSRemotingCreds     = $null
                        }
                        $Session:CredentialHT.Add($Session:ThisRemoteHost,$RHostCredHT)
                    }
    
                    # TODO: Need to remove this when finished testing
                    $PUDRSSyncHT."$Session:ThisRemoteHost`Info".CredHT = $Session:CredentialHT
    
                    # In case this page was refreshed or redirected to from itself, check $Session:CredentialHT for existing values
                    if (!$Local_UserName -and $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds -ne $null) {
                        $Local_UserName = $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds.UserName
                    }
                    if (!$Local_Password -and $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds -ne $null) {
                        $Local_Password = $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds.GetNetworkCredential().Password
                    }
                    if (!$Domain_UserName -and $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds -ne $null) {
                        $Domain_UserName = $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds.UserName
                    }
                    if (!$Domain_Password -and $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds -ne $null) {
                        $Domain_Password = $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds.GetNetworkCredential().Password
                    }
                    if (!$VaultServerUrl -and $Session:CredentialHT.$Session:ThisRemoteHost.VaultServerUrl -ne $null) {
                        $VaultServerUrl = $Session:CredentialHT.$Session:ThisRemoteHost.VaultServerUrl
                    }
                    if (!$Preferred_PSRemotingCredType -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType -ne $null) {
                        $Preferred_PSRemotingCredType = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType
                    }
                    if (!$Preferred_PSRemotingMethod -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod -ne $null) {
                        $Preferred_PSRemotingMethod = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod
                    }
    
                    # Make sure *Something* is filled out...
                    if (!$Local_UserName -and !$Local_Password -and !$Domain_UserName -and !$Domain_Password -and !$VaultServerUrl) {
                        New-UDInputAction -Toast "You MUST enter UserName/Password for either a Local User or Domain User with access to $Session:ThisRemoteHost!" -Duration 10000
                        Sync-UDElement -Id "CredsForm"
                        return
                    }
    
                    <#
                    # Set/Check $Preferred_PSRemotingCredType...
                    if (!$Preferred_PSRemotingCredType -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType) {
                        $Preferred_PSRemotingCredType = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType
                    }
                    # Set/Check $Preferred_PSRemotingMethod...
                    if (!$Preferred_PSRemotingMethod -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod) {
                        $Preferred_PSRemotingMethod = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod
                    }
                    #>
                    
                    if ($Preferred_PSRemotingMethod -eq "SSH") {
                        if ($Preferred_PSRemotingCredType -ne "SSHCertificate") {
                            $Preferred_PSRemotingCredType = "SSHUserNameAndPassword"
                        }
                        
                        if ($Preferred_PSRemotingCredType -eq "Domain") {
                            if ($Local_UserName -or $Local_Password) {
                                New-UDInputAction -Toast "You specifed your Preferred_PSRemotingCredType as '$Preferred_PSRemotingCredType', but you provided Local_UserName or Local_Password!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
                            if ($VaultServerUrl) {
                                New-UDInputAction -Toast "You specifed your Preferred_PSRemotingCredType as '$Preferred_PSRemotingCredType', but you provided VaultServerUrl!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
    
                            if (!$Domain_UserName -or !$Domain_Password) {
                                New-UDInputAction -Toast "You must provide a Domain_UserName AND Domain_Password in order to use PowerShell Remoting over SSH!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
    
                            # Make sure the $Domain_UserName is in format $Session:ThisRemoteHost\$Domain_UserName
                            if ($Domain_UserName -and $Domain_Password) {
                                $DomainShortName = $($PUDRSSyncHT."$Session:ThisRemoteHost`Info".NetworkInfo.Domain -split "\.")[0]
                                if ($Domain_UserName -notmatch "^$DomainShortName\\[a-zA-Z0-9]+$") {
                                    New-UDInputAction -Toast "Domain_UserName must be in format 'Domain\DomainUser'!" -Duration 10000
                                    Sync-UDElement -Id "CredsForm"
                                    return
                                }
            
                                $DomainPwdSecureString = ConvertTo-SecureString $Domain_Password -AsPlainText -Force
                                $DomainAdminCreds = [pscredential]::new($Domain_UserName,$DomainPwdSecureString)
                            }
                        }
                        if ($Preferred_PSRemotingCredType -eq "Local") {
                            if ($Domain_UserName -or $Domain_Password) {
                                New-UDInputAction -Toast "You specifed your Preferred_PSRemotingCredType as '$Preferred_PSRemotingCredType', but you provided Domain_UserName or Domain_Password!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
                            if ($VaultServerUrl) {
                                New-UDInputAction -Toast "You specifed your Preferred_PSRemotingCredType as '$Preferred_PSRemotingCredType', but you provided VaultServerUrl!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
    
                            if (!$Local_UserName -or !$Local_Password) {
                                New-UDInputAction -Toast "You must provide a Local_UserName AND Local_Password in order to use PowerShell Remoting over SSH!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
    
                            # Make sure the $Local_UserName is in format $Session:ThisRemoteHost\$Local_UserName
                            if ($Local_UserName -and $Local_Password) {
                                if ($Local_UserName -notmatch "^$Session:ThisRemoteHost\\[a-zA-Z0-9]+$") {
                                    $Local_UserName = "$Session:ThisRemoteHost\$Local_UserName"
                                }
            
                                $LocalPwdSecureString = ConvertTo-SecureString $Local_Password -AsPlainText -Force
                                $LocalAdminCreds = [pscredential]::new($Local_UserName,$LocalPwdSecureString)
                            }
                        }
                        if ($Preferred_PSRemotingCredType -eq "SSHUserNameAndPassword") {
                            if (!$($Domain_UserName -and $Domain_Password) -and !$($Local_UserName -and $Local_Password)) {
                                New-UDInputAction -Toast "Since you specifed your Preferred_PSRemotingCredType as '$Preferred_PSRemotingCredType', you MUST provide a Domain_UserName and Domain_Password or Local_UserName and Local_Password!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
    
                            # Make sure the $Local_UserName is in format $Session:ThisRemoteHost\$Local_UserName
                            if ($Local_UserName -and $Local_Password) {
                                if ($Local_UserName -notmatch "^$Session:ThisRemoteHost\\[a-zA-Z0-9]+$") {
                                    $Local_UserName = "$Session:ThisRemoteHost\$Local_UserName"
                                }
                                
                                $LocalPwdSecureString = ConvertTo-SecureString $Local_Password -AsPlainText -Force
                                $LocalAdminCreds = [pscredential]::new($Local_UserName,$LocalPwdSecureString)
                            }
    
                            # Make sure the $Domain_UserName is in format $Session:ThisRemoteHost\$Domain_UserName
                            if ($Domain_UserName -and $Domain_Password) {
                                $DomainShortName = $($PUDRSSyncHT."$Session:ThisRemoteHost`Info".NetworkInfo.Domain -split "\.")[0]
                                if ($Domain_UserName -notmatch "^$DomainShortName\\[a-zA-Z0-9]+$") {
                                    New-UDInputAction -Toast "Domain_UserName must be in format 'Domain\DomainUser'!" -Duration 10000
                                    Sync-UDElement -Id "CredsForm"
                                    return
                                }
            
                                $DomainPwdSecureString = ConvertTo-SecureString $Domain_Password -AsPlainText -Force
                                $DomainAdminCreds = [pscredential]::new($Domain_UserName,$DomainPwdSecureString)
                            }
                        }
                        if ($Preferred_PSRemotingCredType -eq "SSHCertificate") {
                            if (!$Domain_UserName -or !$Domain_Password) {
                                New-UDInputAction -Toast "You specifed your Preferred_PSRemotingCredType as '$Preferred_PSRemotingCredType', which means you must provide Domain_UserName and Domain_Password!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
                            if (!$VaultServerUrl) {
                                New-UDInputAction -Toast "You must provide the VaultServerUrl in order to generate/request/receive a new SSH Certificate!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
    
                            # Make sure the $Domain_UserName is in format $Session:ThisRemoteHost\$Domain_UserName
                            if ($Domain_UserName -and $Domain_Password) {
                                $DomainShortName = $($PUDRSSyncHT."$Session:ThisRemoteHost`Info".NetworkInfo.Domain -split "\.")[0]
                                if ($Domain_UserName -notmatch "^$DomainShortName\\[a-zA-Z0-9]+$") {
                                    New-UDInputAction -Toast "Domain_UserName must be in format 'Domain\DomainUser'!" -Duration 10000
                                    Sync-UDElement -Id "CredsForm"
                                    return
                                }
            
                                $DomainPwdSecureString = ConvertTo-SecureString $Domain_Password -AsPlainText -Force
                                $DomainAdminCreds = [pscredential]::new($Domain_UserName,$DomainPwdSecureString)
                            }
    
                            if ($VaultServerUrl) {
                                [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
    
                                # Make sure we can reach the Vault Server and that is in a state where we can actually use it.
                                try {
                                    $VaultServerUpAndUnsealedCheck = Invoke-RestMethod "$VaultServerUrl/sys/health"
                                    if (!$VaultServerUpAndUnsealedCheck -or $VaultServerUpAndUnsealedCheck.initialized -ne $True -or
                                    $VaultServerUpAndUnsealedCheck.sealed -ne $False -or $VaultServerUpAndUnsealedCheck.standby -ne $False) {
                                        throw "The Vault Server is either not reachable or in a state where it cannot be used! Halting!"
                                    }
                                }
                                catch {
                                    New-UDInputAction -Toast $_.Exception.Message -Duration 10000
                                    Sync-UDElement -Id "CredsForm"
                                    return
                                }
                            }
                        }
    
                        if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
                            try {
                                # Make sure we have the WinSSH Module Available
                                if ($(Get-Module -ListAvailable).Name -notcontains "WinSSH") {$null = Install-Module WinSSH -ErrorAction Stop}
                                if ($(Get-Module).Name -notcontains "WinSSH") {$null = Import-Module WinSSH -ErrorAction Stop}
    
                                # Make sure we have the VaultServer Module Available
                                if ($(Get-Module -ListAvailable).Name -notcontains "VaultServer") {$null = Install-Module VaultServer -ErrorAction Stop}
                                if ($(Get-Module).Name -notcontains "VaultServer") {$null = Import-Module VaultServer -ErrorAction Stop}
                            }
                            catch {
                                New-UDInputAction -Toast $_.Exception.Message -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
    
                            if ($(Get-Module).Name -notcontains "WinSSH") {
                                New-UDInputAction -Toast "The WinSSH Module is not available! Halting!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
                            if ($(Get-Module).Name -notcontains "VaultServer") {
                                New-UDInputAction -Toast "The VaultServer Module is not available! Halting!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
    
                            # Install OpenSSH-Win64 if it isn't already
                            if (!$(Test-Path "$env:ProgramFiles\OpenSSH-Win64\ssh.exe")) {
                                Install-WinSSH -GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell pwsh
                            }
                            else {
                                if (!$(Get-Command ssh -ErrorAction SilentlyContinue)) {
                                    $OpenSSHDir ="$env:ProgramFiles\OpenSSH-Win64"
                                    # Update PowerShell $env:Path
                                    [System.Collections.Arraylist][array]$CurrentEnvPathArray = $env:Path -split ';' | Where-Object {![System.String]::IsNullOrWhiteSpace($_)} | Sort-Object | Get-Unique
                                    if ($CurrentEnvPathArray -notcontains $OpenSSHDir) {
                                        $CurrentEnvPathArray.Insert(0,$OpenSSHDir)
                                        $env:Path = $CurrentEnvPathArray -join ';'
                                    }
                                    
                                    # Update SYSTEM Path
                                    $RegistrySystemPath = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment'
                                    $CurrentSystemPath = $(Get-ItemProperty -Path $RegistrySystemPath -Name PATH).Path
                                    [System.Collections.Arraylist][array]$CurrentSystemPathArray = $CurrentSystemPath -split ";" | Where-Object {![System.String]::IsNullOrWhiteSpace($_)} | Sort-Object | Get-Unique
                                    if ($CurrentSystemPathArray -notcontains $OpenSSHDir) {
                                        $CurrentSystemPathArray.Insert(0,$OpenSSHDir)
                                        $UpdatedSystemPath = $CurrentSystemPathArray -join ";"
                                        Set-ItemProperty -Path $RegistrySystemPath -Name PATH -Value $UpdatedSystemPath
                                    }
                                }
                                if (!$(Get-Command ssh -ErrorAction SilentlyContinue)) {
                                    New-UDInputAction -Toast "Unable to find ssh.exe on $env:ComputerName!" -Duration 10000
                                    Sync-UDElement -Id "CredsForm"
                                    return
                                }
                            }
                        }
    
                        if ($Preferred_PSRemotingCredType -eq "SSHCertificate") {
                            # Use Domain Credentials to get a new Vault Server Authentication Token, generate new SSH Keys on the PUDAdminCenter Server,
                            # have the Vault Server sign them, add the new private key to the ssh-agent, and output an SSH Public Certificate to $HOME\.ssh
                            # NOTE: The SSH Keys will expire in 24 hours
                            $NewSSHKeyName = $($DomainAdminCreds.UserName -split "\\")[-1] + "_" + $(Get-Date -Format MM-dd-yy_hhmmsstt)
                            $NewSSHCredentialsSplatParams = @{
                                VaultServerBaseUri                  = $VaultServerUrl
                                DomainCredentialsWithAccessToVault  = $DomainAdminCreds
                                NewSSHKeyName                       = $NewSSHKeyName
                                BlankSSHPrivateKeyPwd               = $True
                                AddToSSHAgent                       = $True
                                RemovePrivateKey                    = $True # Removes the Private Key from the filesystem
                                #SSHAgentExpiry                      = 86400 # 24 hours in seconds # Don't use because this makes ALL keys in ssh-agent expire in 24 hours
                            }
    
                            try {
                                $NewSSHCredsResult = New-SSHCredentials @NewSSHCredentialsSplatParams -ErrorAction Stop
                                $NewSSHCredsResult | Add-Member -Name "PrivateKeyPath" -Value $($NewSSHCredsResult.PublicKeyPath -replace "\.pub","") -MemberType NoteProperty
                            }
                            catch {
                                New-UDInputAction -Toast $_.Exception.Message -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
    
                            if ($PUDRSSyncHT.Keys -contains "NewSSHCredsResult") {
                                $PUDRSSyncHT.NewSSHCredsResult = $NewSSHCredsResult
                            }
                            else {
                                $PUDRSSyncHT.Add("NewSSHCredsResult",$NewSSHCredsResult)
                            }
    
                            # $NewSSHCredsResult (and $GetSSHAuthSanity later on) is a pscustomobject with the following content:
                            <#
                                PublicKeyCertificateAuthShouldWork : True
                                FinalSSHExeCommand                 : ssh zeroadmin@zero@<RemoteHost>
                                PublicKeyPath                      : C:\Users\zeroadmin\.ssh\zeroadmin_071918.pub
                                PublicCertPath                     : C:\Users\zeroadmin\.ssh\zeroadmin_071918-cert.pub
                            #>
    
                            # If $NewSSHCredsResult.FinalSSHExeCommand looks like...
                            #     ssh -o "IdentitiesOnly=true" -i "C:\Users\zeroadmin\.ssh\zeroadmin_071718" -i "C:\Users\zeroadmin\.ssh\zeroadmin_071718-cert.pub" zeroadmin@zero@<RemoteHost>
                            # ...or...
                            #     ssh <user>@<RemoteHost>
                            # ...then there are too many identities loaded in the ssh-agent service, which means we need to get the private key from the registry and write it to a file
                            # See: https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/
                            if (!$NewSSHCredsResult.PublicKeyCertificateAuthShouldWork -or 
                            $NewSSHCredsResult.FinalSSHExeCommand -eq "ssh <user>@<RemoteHost>" -or
                            $NewSSHCredsResult.FinalSSHExeCommand -match "IdentitiesOnly=true"
                            ) {
                                # NOTE: Extract-SSHPrivateKeysFromRegistry is from the WinSSH Module and provides output like:
                                <#
                                    OriginalPrivateKeyFilePath      = $OriginalPrivateKeyFilePath
                                    PrivateKeyContent               = $PrivateKeyContent
                                #>
                                # This should only really be necessary if the ssh-agent has more than 5 entries in it (and the needed key isn't within one of the first 5) and
                                # the RSA Private Key isn't on the filesystem under "$HOME\.ssh". The Get-SSHClientAuthSanity function figures that out for us.
                                $ExtractedPrivateKeys = Extract-SSHPrivateKeysFromRegistry
                                $OriginalPrivateKeyPath = $NewSSHCredsResult.PublicKeyPath -replace "\.pub",""
                                $PrivateKeyContent = $($ExtractedPrivateKeys | Where-Object {$_.OriginalPrivateKeyFilePath -eq $OriginalPrivateKeyPath}).PrivateKeyContent
    
                                if ($PrivateKeyContent.Count -gt 0) {
                                    Set-Content -Path $OriginalPrivateKeyPath -Value $PrivateKeyContent
                                    $NeedToRemovePrivateKey = $True
                                    $GetSSHAuthSanityCheck = Get-SSHClientAuthSanity -SSHPublicKeyFilePath $NewSSHCredsResult.PublicKeyPath
                                    if ($GetSSHAuthSanityCheck.PublicKeyCertificateAuthShouldWork) {
                                        $GetSSHAuthSanity = [pscustomobject]@{
                                            PublicKeyCertificateAuthShouldWork  = $True
                                            FinalSSHExeCommand                  = $GetSSHAuthSanityCheck.FinalSSHExeCommand
                                            PrivateKeyPath                      = $OriginalPrivateKeyPath
                                            PublicKeyPath                       = $NewSSHCredsResult.PublicKeyPath
                                            PublicCertPath                      = $NewSSHCredsResult.PublicKeyPath + '-cert.pub'
                                        }
                                    }
                                    
                                    # The below $FinalSSHExeCommand string should look like:
                                    #     ssh -o "IdentitiesOnly=true" -i "$OriginalPrivateKeyPath" -i "$($NewSSHCredsResult.PublicCertPath)" zeroadmin@zero@<RemoteHost>
                                    $FinalSSHExeCommand = $GetSSHAuthSanity.FinalSSHExeCommand
    
                                    if (!$GetSSHAuthSanity.PublicKeyCertificateAuthShouldWork) {
                                        $UserNamePasswordRequired = $True
                                        $ToastMsg = "Unable to use SSH Certificate Authentication because the user ssh private key is not available on the " +
                                        "filesystem or in the ssh-agent. Trying UserName/Password SSH Authentication..."
                                        New-UDInputAction -Toast $ToastMsg -Duration 10000
                                        #Sync-UDElement -Id "CredsForm"
                                        #return
                                    }
                                }
                                else {
                                    $UserNamePasswordRequired = $True
                                    $ToastMsg = "Unable to use SSH Certificate Authentication because the user ssh keys and/or " +
                                    "ssh cert and/or ssh-agent is not configured properly! Trying UserName/Password SSH Authentication..."
                                    New-UDInputAction -Toast $ToastMsg -Duration 10000
                                    #Sync-UDElement -Id "CredsForm"
                                    #return
                                }
                            }
                            else {
                                $GetSSHAuthSanity = $NewSSHCredsResult
                                
                                # The below $FinalSSHExeCommand string should look like:
                                #     ssh zeroadmin@zero@<RemoteHost>
                                $FinalSSHExeCommand = $GetSSHAuthSanity.FinalSSHExeCommand
                            }
    
                            $SSHCertificate = Get-Content $GetSSHAuthSanity.PublicCertPath
    
                            if ($PUDRSSyncHT.Keys -contains "GetSSHAuthSanity") {
                                $PUDRSSyncHT.GetSSHAuthSanity = $GetSSHAuthSanity
                            }
                            else {
                                $PUDRSSyncHT.Add("GetSSHAuthSanity",$GetSSHAuthSanity)
                            }
                        }
                    }
                    if ($Preferred_PSRemotingMethod -eq "WinRM") {
                        if ($VaultServerUrl) {
                            New-UDInputAction -Toast "You provided a Vault Server Url, however, your Preferred_PSRemotingMethod is not SSH!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }
    
                        if ($($Local_UserName -and !$Local_Password) -or $(!$Local_UserName -and $Local_Password) -or
                        $($Domain_UserName -and !$Domain_Password) -or $(!$Domain_UserName -and $Domain_Password)
                        ) {
                            New-UDInputAction -Toast "Please enter both a UserName and a Password!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }
    
                        # Make sure the $Local_UserName is in format $Session:ThisRemoteHost\$Local_UserName
                        if ($Local_UserName -and $Local_Password) {
                            if ($Local_UserName -notmatch "^$Session:ThisRemoteHost\\[a-zA-Z0-9]+$") {
                                $Local_UserName = "$Session:ThisRemoteHost\$Local_UserName"
                            }
        
                            $LocalPwdSecureString = ConvertTo-SecureString $Local_Password -AsPlainText -Force
                            $LocalAdminCreds = [pscredential]::new($Local_UserName,$LocalPwdSecureString)
                        }
    
                        # Make sure the $Domain_UserName is in format $Session:ThisRemoteHost\$Domain_UserName
                        if ($Domain_UserName -and $Domain_Password) {
                            $DomainShortName = $($PUDRSSyncHT."$Session:ThisRemoteHost`Info".NetworkInfo.Domain -split "\.")[0]
                            if ($Domain_UserName -notmatch "^$DomainShortName\\[a-zA-Z0-9]+$") {
                                New-UDInputAction -Toast "Domain_UserName must be in format 'Domain\DomainUser'!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
        
                            $DomainPwdSecureString = ConvertTo-SecureString $Domain_Password -AsPlainText -Force
                            $DomainAdminCreds = [pscredential]::new($Domain_UserName,$DomainPwdSecureString)
                        }
                    }
    
                    ##### Test the Credentials #####
    
                    # IMPORTANT NOTE: OpenSSH-Win64's implementation of 'ssh.exe -t' does not work properly...If it did, the TestSSH Private function would be a lot simpler
                                
                    # NOTE: The Principal(s) on the SSH Certificate do NOT determine who you are on the Remote Host. What DOES determine who you are on the Remote Host is
                    # 1) The UserName specified via -UserName with *-PSSession cmdlets
                    # 2) The UserName specified via <UserName>@<DomainShortName>@<RemoteHost> with ssh.exe
    
                    if ($Preferred_PSRemotingMethod -eq "SSH") {
                        if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
                            # Make sure we have pwsh
                            if (!$(Get-Command pwsh -ErrorAction SilentlyContinue)) {
                                $InstallPwshResult = Install-Program -ProgramName powershell-core -CommandName pwsh.exe -ExpectedInstallLocation "C:\Program Files\PowerShell"
                            }
                            
                            # NOTE: The Await Module comes with the WinSSH Module that we made sure was installed/imported earlier
                            try {
                                Import-Module "$($(Get-Module WinSSH).ModuleBase)\Await\Await.psd1" -ErrorAction Stop
                            }
                            catch {
                                New-UDInputAction -Toast "Unable to load the Await Module! Halting!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
                        }
    
                        if ($Preferred_PSRemotingCredType -eq "SSHCertificate") {
                            # Determine if we're going to do UserName/Password Auth or SSH Certificate Auth
                            if (!$UserNamePasswordRequired) {
                                # We need to get the UserName from the SSHCertificate
                                [System.Collections.ArrayList][array]$SSHCertInfo = ssh-keygen -L -f $GetSSHAuthSanity.PublicCertPath
                                $PrincipalsLine = $SSHCertInfo | Where-Object {$_ -match "Principals:"}
                                $PrincipalsLineIndex = $SSHCertInfo.IndexOf($PrincipalsLine)
                                $CriticalOptionsLine = $SSHCertInfo | Where-Object {$_ -match "Critical Options:"}
                                $CriticalOptionsLineIndex = $SSHCertInfo.IndexOf($CriticalOptionsLine)
                                [array]$PrincipalsList = @($SSHCertInfo[$PrincipalsLineIndex..$CriticalOptionsLineIndex] | Where-Object {$_ -notmatch "Principals:|Critical Options:"} | foreach {$_.Trim()})
                                $SSHCertUser = $($PrincipalsList[0] -split '@')[0].Trim()
                                $ShortUserName = $SSHCertUser
                                $DomainShortName = $($($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $Session:ThisRemoteHost}).Domain -split "\.")[0]
                                $Domain_UserName = "$DomainShortName\$ShortUserName"
                            }
                        }
    
                        $OSGuess = $PUDRSSyncHT."$Session:ThisRemoteHost`Info".RHostTableData.OS_Guess
                        if ($OSGuess) {
                            if ($OSGuess -match "Windows|Microsoft") {
                                $UpdatedOSGuess = "Windows"
                            }
                            elseif ($OSGuess -match "Linux") {
                                $UpdatedOSGuess = "Linux"
                            }
                            else {
                                $UpdatedOSGuess = "Windows"
                            }
                        }
                        if (!$OSGuess) {
                            $UpdatedOSGuess = "Windows"
                        }
    
                        $SSHTestSplatParams = @{
                            OSGuess                 = $UpdatedOSGuess
                            RemoteHostNetworkInfo   = $PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $Session:ThisRemoteHost}
                            OutputTracker           = $PUDRSSyncHT
                        }
                        if ($Local_UserName -and $Local_Password) {
                            $SSHTestSplatParams.Add("LocalUserName",$Local_UserName)
                            $SSHTestSplatParams.Add("LocalPassword",$Local_Password)
                        }
                        if ($Domain_UserName -and $Domain_Password) {
                            $SSHTestSplatParams.Add("DomainUserName",$Domain_UserName)
                            $SSHTestSplatParams.Add("DomainPassword",$Domain_Password)
                        }
                        if ($GetSSHAuthSanity.PublicCertPath) {
                            $SSHTestSplatParams.Add("PublicCertPath",$GetSSHAuthSanity.PublicCertPath)
                        }
                        # IMPORTANT NOTE: The SSHTest function outputs some UDDashboard objects and sets $script:SSHCheckAsJson as well as $script:SSHOutputPrep
                        # For these reasons, we are assigning SSHTest output to a variable
                        TestSSH @SSHTestSplatParams
    
                        if ($SSHCheckAsJson.Output -ne "ConnectionSuccessful" -and ![bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful")) {
                            New-UDInputAction -Toast "SSH attempts via PowerShell Core 'Invoke-Command' and ssh.exe have failed!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }
    
                        if ($SSHCheckAsJson.Output -eq "ConnectionSuccessful") {
                            $PUDRSSyncHT."$Session:ThisRemoteHost`Info".PSRemotingOverSSHWorks = $True
    
                            if ($SSHCheckAsJson.Platform -eq "Win32NT") {
                                $OSDetermination = "Windows"
                                $ShellDetermination = "pwsh"
                            }
                            else {
                                $OSDetermination = "Linux"
                                $ShellDetermination = "bash"
                            }
    
                            $PUDRSSyncHT."$Session:ThisRemoteHost`Info".OSDetermination = $OSDetermination
                            $PUDRSSyncHT."$Session:ThisRemoteHost`Info".ShellDetermination = $ShellDetermination
    
                        }
                        if ([bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful")) {
                            $PUDRSSyncHT."$Session:ThisRemoteHost`Info".PSRemotingOverSSHWorks = $False
    
                            if ($SSHOutputPrep -match "Microsoft|Windows|Win32NT") {
                                $OSDetermination = "Windows"
                                if ($SSHOutputPrep -match "PSEdition" -and $SSHOutputPrep -match "Core") {
                                    $ShellDetermination = "pwsh"
                                }
                                elseif ($SSHOutputPrep -match "PSEdition" -and $SSHOutputPrep -match "Desktop") {
                                    $ShellDetermination = "powershell"
                                }
                                else {
                                    $ShellDetermination = "cmd"
                                }
                            }
                            else {
                                $OSDetermination = "Linux"
                                $ShellDetermination = "bash"
                            }
    
                            $PUDRSSyncHT."$Session:ThisRemoteHost`Info".OSDetermination = $OSDetermination
                            $PUDRSSyncHT."$Session:ThisRemoteHost`Info".ShellDetermination = $ShellDetermination
    
                            # Try and setup PSRemoting on the remote host by using 'ssh -t' script
                            # NOTE: we have $SSHCmdString thanks to the 'TestSSH' private function used above
                            # $SSHCmdString looks like this:
                            #   ssh -t zeroadmin@zero@192.168.2.49 "$InstallPwshScript"
                            [System.Collections.ArrayList][array]$SSHCmdStringSansScript = $($SSHCmdString -split "`n")[0..2]
    
                            if ($OSDetermination -eq "Windows") {
                                # Sudo is NOT an issue on Windows, so we can install/configure pwsh PSRemoting via SSH immediately.
    
                                # $($SSHCmdStringSansScript -join " ") should look like this:
                                #   ssh -t zeroadmin@zero@192.168.2.49
                                try {
                                    $null = Configure-PwshRemotingViaSSH -Platform $OSDetermination -Shell $ShellDetermination -SSHCmdOptions $($SSHCmdStringSansScript -join " ") -ErrorAction Stop
                                }
                                catch {
                                    New-UDInputAction -Toast $_.Exception.Message -Duration 10000
                                    Sync-UDElement -Id "CredsForm"
                                    return
                                }
                            }
                            if ($OSDetermination -eq "Linux") {
                                # We cannot run 'sudo' in a PSSession on Linux. However, from within a non-elevated pwsh PSSession, we can do something like:
                                #     $InstallModuleResultPrep = sudo pwsh -c "Install-Module Whatever -Force; Get-Module -ListAvailable Whatever | ConvertTo-Json"
                                #     $InstallModuleResult = $InstallModuleResultPrep | ConvertFrom-Json
                                # The problem with this approach is we're still going to be prompted for a sudo password. However, we CAN add some settings to
                                # /etc/sudoers to allow THIS particular user to run ONLY THE COMMAND 'sudo pwsh -c' without being prompted for a sudo password.
                                # The setting(s) to do this in /etc/sudoers should look like this...
                                <#
                                    Cmnd_Alias SUDO_PWSH = /bin/pwsh
                                    Defaults!SUDO_PWSH !requiretty
                                    %zero\\zeroadmin ALL=(ALL) NOPASSWD: SUDO_PWSH
                                #>
                                # ... where zero\zeroadmin is the user that we want to give permission to run 'sudo pwsh -c' without being prompted for a password.
    
                                # First, make sure the user has sudo privileges. If not, we have to fail immediately.
                                $CheckSudoStatusResult = CheckSudoStatus -UserNameShort -DomainNameShort -RemoteHostName
                                if ($CheckSudoStatusResult -eq "PasswordPrompt") {
                                    $null = RemoveSudoPwd -UserNameShort -DomainNameShort -RemoteHostName -SudoPwd
                                }
                            }
                        }
    
                        # If PSRemoting doesn't work...
                    }
                    if ($Preferred_PSRemotingMethod -eq "WinRM") {
                        [System.Collections.ArrayList]$CredentialsToTest = @()
                        if ($LocalAdminCreds) {
                            $PSObj = [pscustomobject]@{CredType = "LocalUser"; PSCredential = $LocalAdminCreds}
                            $null = $CredentialsToTest.Add($PSObj)
                        }
                        if ($DomainAdminCreds) {
                            $PSObj = [pscustomobject]@{CredType = "DomainUser"; PSCredential = $DomainAdminCreds}
                            $null = $CredentialsToTest.Add($PSObj)
                        }
    
                        [System.Collections.ArrayList]$FailedCredentialsA = @()
                        foreach ($CredObj in $CredentialsToTest) {
                            try {
                                $GetWorkingCredsResult = GetWorkingCredentials -RemoteHostNameOrIP $Session:ThisRemoteHost -AltCredentials $CredObj.PSCredential -ErrorAction Stop
                
                                if ($GetWorkingCredsResult.DeterminedCredsThatWorkedOnRemoteHost) {
                                    if ($GetWorkingCredsResult.WorkingCredentials.GetType().FullName -ne "System.Management.Automation.PSCredential") {
                                        #New-UDInputAction -Toast "$($CredObj.CredType) Credentials are not valid! Please try again." -Duration 10000
                                        $null = $FailedCredentialsA.Add($CredObj)
                                    }
                                }
                                else {
                                    $null = $FailedCredentialsA.Add($CredObj)
                                }
                            }
                            catch {
                                #New-UDInputAction -Toast $_.Exception.Message -Duration 10000
                                #New-UDInputAction -Toast "Unable to test $($CredObj.CredType) Credentials! Refreshing page..." -Duration 10000
                                #New-UDInputAction -RedirectUrl "/PSRemotingCreds/$Session:ThisRemoteHost"
                            }
                        }
    
                        if ($($CredentialsToTest.Count -eq 2 -and $FailedCredentialsA.Count -eq 2) -or 
                        $($CredentialsToTest.Count -eq 1 -and $FailedCredentialsA.Count -eq 1)
                        ) {
                            # Since WinRM failed, try and enable WinRM Remotely via Invoke-WmiMethod over RPC Port 135 (if it's open)
                            $RPCPortOpen = $(TestPort -HostName $Session:ThisRemoteHost -Port 135).Open
    
                            [System.Collections.ArrayList]$EnableWinRMSuccess = @()
                            foreach ($CredObj in $CredentialsToTest) {
                                if ($RPCPortOpen) {
                                    try {
                                        $null = EnableWinRMViaRPC -RemoteHostNameOrIP $Session:ThisRemoteHost -Credential $CredObj.PSCredential
                                        $null = $EnableWinRMSuccess.Add($CredObj)
                                        break
                                    }
                                    catch {
                                        #New-UDInputAction -Toast "Failed to enable WinRM Remotely using Credentials $($CredObj.PSCredential.UserName)" -Duration 10000
                                    }
                                }
                            }
    
                            if ($EnableWinRMSuccess.Count -eq 0) {
                                New-UDInputAction -Toast "Unable to Enable WinRM on $Session:ThisRemoteHost via Invoke-WmiMethod over RPC! Please check your credentials." -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
                            else {
                                [System.Collections.ArrayList]$FailedCredentialsB = @()
                                foreach ($CredObj in $CredentialsToTest) {
                                    try {
                                        $GetWorkingCredsResult = GetWorkingCredentials -RemoteHostNameOrIP $Session:ThisRemoteHost -AltCredentials $CredObj.PSCredential -ErrorAction Stop
                        
                                        if ($GetWorkingCredsResult.WorkingCredentials.GetType().FullName -ne "System.Management.Automation.PSCredential") {
                                            #New-UDInputAction -Toast "$($CredObj.CredType) Credentials are not valid! Please try again." -Duration 10000
                                            $null = $FailedCredentialsB.Add($CredObj)
                                        }
                                    }
                                    catch {
                                        New-UDInputAction -Toast $_.Exception.Message -Duration 10000
                                        New-UDInputAction -Toast "Unable to test $($CredObj.CredType) Credentials! Please try again." -Duration 10000
                                        Sync-UDElement -Id "CredsForm"
                                        return
                                    }
                                }
                            }
                        }
    
                        if ($FailedCredentialsA.Count -gt 0 -or $FailedCredentialsB.Count -gt 0) {
                            if ($FailedCredentialsB.Count -gt 0) {
                                foreach ($CredObj in $FailedCredentialsB) {
                                    New-UDInputAction -Toast "$($CredObj.CredType) Credentials are not valid! Please try again." -Duration 10000
                                    $Session:CredentialHT.$Session:ThisRemoteHost."$CredType`Creds" = $null
                                }
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
                            if ($FailedCredentialsA.Count -gt 0 -and $FailedCredentialsB.Count -eq 0) {
                                foreach ($CredObj in $FailedCredentialsA) {
                                    New-UDInputAction -Toast "$($CredObj.CredType) Credentials are not valid! Please try again." -Duration 10000
                                    $Session:CredentialHT.$Session:ThisRemoteHost."$CredType`Creds" = $null
                                }
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
                        }
                    }
    
                    if ($DomainAdminCreds) {
                        $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds = $DomainAdminCreds
                    }
                    if ($LocalAdminCreds) {
                        $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds = $LocalAdminCreds
                    }
                    if ($VaultServerUrl) {
                        $Session:CredentialHT.$Session:ThisRemoteHost.VaultServerUrl = $VaultServerUrl
                    }
                    if ($Preferred_PSRemotingCredType) {
                        $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType = $Preferred_PSRemotingCredType
                    }
                    if ($Preferred_PSRemotingMethod) {
                        $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod = $Preferred_PSRemotingMethod
                    }
    
                    # Determine $PSRemotingCreds
                    if ($Preferred_PSRemotingCredType -eq "Local") {
                        $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds = $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds
                    }
                    if ($Preferred_PSRemotingCredType -eq "Domain") {
                        $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds = $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds
                    }
    
                    if ($Preferred_PSRemotingMethod -eq "SSH") {
                        if (!$PUDRSSyncHT."$Session:ThisRemoteHost`Info".PSRemotingWorks) {
                            New-UDInputAction -Toast "SSH was SUCCESSFUL, however, ssh functionality has not been fully implemented yet. Please use WinRM instead." -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }
                    }
    
                    New-UDInputAction -RedirectUrl "/ToolSelect/$Session:ThisRemoteHost"
                }
                $Cache:CredsForm
    
                New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                    try {
                        $null = $Session:PSRemotingPageLoadingTracker.Add("FinishedLoading")
                    }
                    catch {
                        Write-Verbose "`$Session:PSRemotingPageLoadingTracker hasn't been set yet..."
                    }
                }
            }
            New-UDColumn -Size 2 -EndPoint {}
        }
    }
    $Page = New-UDPage -Url "/PSRemotingCreds/:RemoteHost" -Endpoint $PSRemotingCredsPageContent
    $null = $Pages.Add($Page)
    
    #region >> Tool Select Page
    
    $ToolSelectPageContent = {
        param($RemoteHost)
    
        New-UDColumn -Endpoint {$Session:ThisRemoteHost = $RemoteHost}
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, we can't use the $DisconnectedPageContent directly here. It needs to be a different object before it actually outputs
        # UD Elements. Not sure why.
        $RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else 
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:ToolSelectPageLoadingTracker = [System.Collections.ArrayList]::new()
                #$PUDRSSyncHT.ToolSelectPageLoadingTracker = $Session:ToolSelectPageLoadingTracker
            }
            #New-UDHeading -Text "Select a Tool" -Size 4
        }
    
        New-UDRow -Columns {
            New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                if ($Session:ToolSelectPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            $RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $Session:ThisRemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/PSRemotingCreds/$Session:ThisRemoteHost"
                #Write-Error "Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds is null"
            }
            else {
                # Check $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds Credentials. If they don't work, redirect to "/PSRemotingCreds/$Session:ThisRemoteHost"
                try {
                    $GetWorkingCredsResult = GetWorkingCredentials -RemoteHostNameOrIP $RHostIP -AltCredentials $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds -ErrorAction Stop
    
                    if ($GetWorkingCredsResult.DeterminedCredsThatWorkedOnRemoteHost) {
                        if ($GetWorkingCredsResult.WorkingCredentials.GetType().FullName -ne "System.Management.Automation.PSCredential") {
                            Invoke-UDRedirect -Url "/PSRemotingCreds/$Session:ThisRemoteHost"
                            #Write-Error "GetWorkingCredentials A"
                        }
                    }
                    else {
                        Invoke-UDRedirect -Url "/PSRemotingCreds/$Session:ThisRemoteHost"
                        #Write-Error "GetWorkingCredentials B"
                    }
                }
                catch {
                    Invoke-UDRedirect -Url "/PSRemotingCreds/$Session:ThisRemoteHost"
                    #Write-Error $_
                }
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $Session:ThisRemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                Invoke-UDRedirect -Url "/Disconnected/$Session:ThisRemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","CredSSP","DateTime") -AutoRefresh -RefreshInterval 5 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $Session:ThisRemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $Session:ThisRemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                <#
                                $TableData = @{
                                    RemoteHost      = $Session:ThisRemoteHost.ToUpper()
                                    Status          = "Disconnected"
                                }
                                #>
                                Invoke-UDRedirect -Url "/Disconnected/$Session:ThisRemoteHost"
                            }
    
                            #region >> Gather Some Initial Info From $Session:ThisRemoteHost
    
                            $GetServerInventoryFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ServerInventory" -and $_ -notmatch "function Get-PUDAdminCenter"}
                            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                Invoke-Expression $using:GetServerInventoryFunc
    
                                [pscustomobject]@{ServerInventoryStatic = Get-ServerInventory}
                            }
                            $Session:ServerInventoryStatic = $StaticInfo.ServerInventoryStatic
                            $PUDRSSyncHT."$Session:ThisRemoteHost`Info".ServerInventoryStatic = $Session:ServerInventoryStatic
    
                            #endregion >> Gather Some Initial Info From $Session:ThisRemoteHost
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataTracker.Previous = $PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataTracker.Previous = $PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataTracker.Current = $PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataRSInfo.LiveOutput.Clone()
                            }
                            
                            if ($PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataTracker.Previous.Count -eq 0) {
                                if ($Session:ServerInventoryStatic.IsCredSSPEnabled) {
                                    $CredSSPStatus = "Enabled"
                                }
                                else {
                                    $CredSSPStatus = "Disabled"
                                }
                            }
                            elseif (@($PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataTracker.Previous.ServerInventory).Count -gt 0) {
                                if (@($PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataTracker.Previous.ServerInventory)[-1].IsCredSSPEnabled) {
                                    $CredSSPStatus = "Enabled"
                                }
                                else {
                                    $CredSSPStatus = "Disabled"
                                }
                            }
                            else {
                                $CredSSPStatus = "NotYetDetermined"
                            }
                            $TableData.Add("CredSSP",$CredSSPStatus)
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","CredSSP","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected to $Session:ThisRemoteHost
    
            #region >> Create the Tool Select Content
            
            if ($ConnectionStatus -eq "Connected") {
                [System.Collections.ArrayList]$DynPageRows = @()
                $RelevantDynamicPages = $DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"}
                $ItemsPerRow = 3
                $NumberOfRows = $DynamicPages.Count / $ItemsPerRow
                for ($i=0; $i -lt $NumberOfRows; $i++) {
                    New-Variable -Name "Row$i" -Value $(New-Object System.Collections.ArrayList) -Force
    
                    if ($i -eq 0) {$j = 0} else {$j = $i * $ItemsPerRow}
                    $jLoopLimit = $j + $($ItemsPerRow - 1)
                    while ($j -le $jLoopLimit) {
                        $null = $(Get-Variable -Name "Row$i" -ValueOnly).Add($RelevantDynamicPages[$j])
                        $j++
                    }
    
                    $null = $DynPageRows.Add($(Get-Variable -Name "Row$i" -ValueOnly))
                }
    
                foreach ($DynPageRow in $DynPageRows) {
                    New-UDRow -Endpoint {
                        foreach ($DynPage in $DynPageRow) {
                            # Make sure we're connected before loadting the UDCards
                            $DynPageNoSpace = $DynPage -replace "[\s]",""
                            $CardId = $DynPageNoSpace + "Card"
                            New-UDColumn -Size 4 -Endpoint {
                                if ($DynPage -ne $null) {
                                    $Links = @(New-UDLink -Text $DynPage -Url "/$DynPageNoSpace/$Session:ThisRemoteHost" -Icon dashboard)
                                    New-UDCard -Title $DynPage -Id $CardId -Text "$DynPage Info" -Links $Links
                                }
                            }
                        }
                    }
                }
    
                $null = $Session:ToolSelectPageLoadingTracker.Add("FinishedLoading")
            }
    
            #endregion >> Create the Tool Select Content
        }
    }
    $Page = New-UDPage -Url "/ToolSelect/:RemoteHost" -Endpoint $ToolSelectPageContent
    $null = $Pages.Add($Page)
    
    #endregion >> Tool Select Page
    

    #endregion >> Dynamic Pages


    #region >> Static Pages

    #region >> Create Home Page
    
    $HomePageContent = {
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Define some Cache: variables that we'll be using in a lot of different contexts
        $Cache:ThisModuleFunctionsStringArray = $ThisModuleFunctionsStringArray = $(Get-Module PUDAdminCenter).Invoke({$FunctionsForSBUse})
    
        $Cache:DynamicPages = $DynamicPages = @(
            "PSRemotingCreds"
            "ToolSelect"
            "Overview"
            "Certificates"
            "Devices"
            "Events"
            "Files"
            "Firewall"
            "Users And Groups"
            "Network"
            "Processes"
            "Registry"
            "Roles And Features"
            "Scheduled Tasks"
            "Services"
            "Storage"
            "Updates"
        )
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
        New-UDColumn -EndPoint {$Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}}
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Cache:RHostRefreshAlreadyRan = $False
                $Session:HomePageLoadingTracker = $False
                $Session:SearchRemoteHosts = $False
            }
            New-UDHeading -Text "Home" -Size 4
        }
    
        New-UDRow -Columns {
            New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                if (!$Session:HomePageLoadingTracker) {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        #region >> HomePage Main Content
    
        New-UDRow -Endpoint {
            New-UDColumn -Endpoint {
                New-UDHeading -Text "General Network Scan" -Size 5
                New-UDElement -Id "ScanNetwork" -Tag div -EndPoint {
                    if ($Session:ScanNetwork) {
                        New-UDHeading -Text "Scanning Network for RemoteHosts...Please wait..." -Size 6
                        New-UDPreloader -Size small
                    }
                }
            }
        }
        New-UDRow -Endpoint {
            New-UDColumn -Endpoint {
                New-UDButton -Text "Scan Network" -OnClick {
                    $Session:ScanNetwork = $True
                    Sync-UDElement -Id "ScanNetwork"
    
                    if ($PSVersionTable.Platform -eq "Unix") {
                        [System.Collections.ArrayList]$ScanRemoteHostListPrep = GetComputerObjectsInLDAP -ObjectCount 100 -LDAPCreds $PUDRSSyncHT.LDAPCreds
                    }
                    else {
                        [System.Collections.ArrayList]$ScanRemoteHostListPrep = $(GetComputerObjectsInLDAP -ObjectCount 100).Name
                    }
    
                    # Let's just get 20 of them initially. We want *something* on the HomePage but we don't want hundreds/thousands of entries. We want
                    # the user to specify individual/range of hosts/devices that they want to manage.
                    #$ScanRemoteHostListPrep = $ScanRemoteHostListPrep[0..20]
                    if ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Win32NT") {
                        [System.Collections.ArrayList]$ScanRemoteHostListPrep = $ScanRemoteHostListPrep | foreach {$_ -replace "CN=",""}
                    }
                    if ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Unix") {
                        [System.Collections.ArrayList]$ScanRemoteHostListPrep = $ScanRemoteHostListPrep | foreach {$($_ -replace "cn: ","").Trim()}
                    }
    
                    # Filter Out the Remote Hosts that we can't resolve
                    [System.Collections.ArrayList]$ScanRemoteHostList = @()
    
                    $null = Clear-DnsClientCache
                    foreach ($HName in $ScanRemoteHostListPrep) {
                        try {
                            $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $HName -ErrorAction Stop
    
                            if ($RemoteHostNetworkInfo.HostName -eq "localhost") {
                                $HostNameOutput = hostname
                                $HostNameShort = if ($HostNameOutput -match "\.") {$($HostNameOutput -split "\.")[0]} else {$HostNameOutput}
                                [System.Collections.ArrayList][array]$IPAddresses = Get-NetworkInfo -InterfaceStatus Up -AddressFamily IPv4 | foreach {$_.Address.IPAddressToString}
                
                                $RemoteHostNetworkInfo.FQDN = $HostNameOutput
                                $RemoteHostNetworkInfo.HostName = $HostNameShort
                                $RemoteHostNetworkInfo.IPAddressList = $IPAddresses
                                $RemoteHostNetworkInfo.Domain = GetDomainName
                            }
    
                            # ResolveHost will NOT throw an error even if it can't figure out HostName, Domain, or FQDN as long as $IPAddr IS pingable
                            # So, we need to do the below to compensate for code downstream that relies on HostName, Domain, and FQDN
                            if (!$RemoteHostNetworkInfo.HostName) {
                                $IPAddr = $RemoteHostNetworkInfo.IPAddressList[0]
                                $LastTwoOctets = $($IPAddr -split '\.')[2..3] -join 'Dot'
                                $UpdatedHostName = NewUniqueString -PossibleNewUniqueString "Unknown$LastTwoOctets" -ArrayOfStrings $PUDRSSyncHT.RemoteHostList.HostName
                                $RemoteHostNetworkInfo.HostName = $UpdatedHostName
                                $RemoteHostNetworkInfo.FQDN = $UpdatedHostName + '.Unknown'
                                $RemoteHostNetworkInfo.Domain = 'Unknown'
                            }
    
                            if ($ScanRemoteHostList.FQDN -notcontains $RemoteHostNetworkInfo.FQDN) {
                                $null = $ScanRemoteHostList.Add($RemoteHostNetworkInfo)
                            }
                        }
                        catch {
                            continue
                        }
                    }
    
                    $PUDRSSyncHT.RemoteHostList = $ScanRemoteHostList
    
                    if ($PUDRSSyncHT.Keys -contains "ScanRemoteHostList") {
                        $PUDRSSyncHT.ScanRemoteHostList = $ScanRemoteHostList
                    }
                    else {
                        $PUDRSSyncHT.Add("ScanRemoteHostList",$ScanRemoteHostList)
                    }
    
                    # Add Keys for each of the Remote Hosts in the $InitialRemoteHostList    
                    foreach ($RHost in $ScanRemoteHostList) {
                        $Key = $RHost.HostName + "Info"
                        if ($PUDRSSyncHT.Keys -notcontains $Key) {
                            $Value = @{
                                NetworkInfo                 = $RHost
                                CredHT                      = $null
                                ServerInventoryStatic       = $null
                                RelevantNetworkInterfaces   = $null
                                LiveDataRSInfo              = $null
                                LiveDataTracker             = @{Current = $null; Previous = $null}
                            }
                            foreach ($DynPage in $($DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                $DynPageHT = @{
                                    LiveDataRSInfo      = $null
                                    LiveDataTracker     = @{Current = $null; Previous = $null}
                                }
                                $Value.Add($($DynPage -replace "[\s]",""),$DynPageHT)
                            }
                            $PUDRSSyncHT.Add($Key,$Value)
                        }
                    }
    
                    $Session:ScanNetwork = $False
                    Sync-UDElement -Id "ScanNetwork"
    
                    # Refresh the Main Content
                    Sync-UDElement -Id "MainContent"
                }
            }
        }
    
        # RemoteHost / Device Search
        New-UDRow -Endpoint {
            New-UDColumn -Endpoint {
                New-UDHeading -Text "Find Specific Remote Hosts" -Size 5
                New-UDElement -Id "SearchRemoteHosts" -Tag div -EndPoint {
                    if ($Session:SearchRemoteHosts) {
                        New-UDHeading -Text "Searching for RemoteHosts...Please wait..." -Size 6
                        New-UDPreloader -Size small
                    }
                }
            }
    
            New-UDColumn -Size 12 -Endpoint {
                New-UDRow -Endpoint {
                    New-UDColumn -Size 5 -Endpoint {
                        New-UDTextbox -Id "HostNameOrFQDN" -Label "HostName_Or_FQDN" -Placeholder "Enter a HostName/FQDN, or comma-separated HostNames/FQDNs"
                    }
                    New-UDColumn -Size 5 -Endpoint {
                        New-UDTextbox -Id "IPAddress" -Label "IPAddress" -Placeholder "Enter an IP, comma-separated IPs, a range of IPs using a '-', or a range of IPs using CIDR"
                    }
                    New-UDColumn -Size 2 -Endpoint {
                        New-UDButton -Text "Search" -OnClick {
                            $Session:SearchRemoteHosts = $True
                            Sync-UDElement -Id "SearchRemoteHosts"
    
                            $HostNameTextBox = Get-UDElement -Id "HostNameOrFQDN"
                            $IPTextBox = Get-UDElement -Id "IPAddress"
    
                            if ($PUDRSSyncHT.Keys -contains "HostNameTextBox") {
                                $PUDRSSyncHT.HostNameTextBox = $HostNameTextBox
                            }
                            else {
                                $PUDRSSyncHT.Add("HostNameTextBox",$HostNameTextBox)
                            }
    
                            if ($PUDRSSyncHT.Keys -contains "IPTextBox") {
                                $PUDRSSyncHT.IPTextBox = $IPTextBox
                            }
                            else {
                                $PUDRSSyncHT.Add("IPTextBox",$IPTextBox)
                            }
    
                            $HostNames = $HostNameTextBox.Attributes['value']
                            $IPAddresses = $IPTextBox.Attributes['value']
    
                            if ($PUDRSSyncHT.Keys -contains "HostNames") {
                                $PUDRSSyncHT.HostNames = $HostNames
                            }
                            else {
                                $PUDRSSyncHT.Add("HostNames",$HostNames)
                            }
    
                            if ($PUDRSSyncHT.Keys -contains "IPAddresses") {
                                $PUDRSSyncHT.IPAddresses = $IPAddresses
                            }
                            else {
                                $PUDRSSyncHT.Add("IPAddresses",$IPAddresses)
                            }
    
                            [System.Collections.ArrayList]$RemoteHostListPrep = @()
    
                            if ($HostNames) {
                                if ($HostNames -match [regex]::Escape(',')) {
                                    $HostNames -split [regex]::Escape(',') | foreach {
                                        if (![System.String]::IsNullOrWhiteSpace($_)) {
                                            $null = $RemoteHostListPrep.Add($_.Trim())
                                        }
                                    }
                                }
                                else {
                                    $null = $RemoteHostListPrep.Add($HostNames.Trim())
                                }
                            }
    
                            if ($IPAddresses) {
                                # Do some basic validation. Make sure no unexpected characters are present.
                                $UnexpectedCharsCheck = $([char[]]$IPAddresses -notmatch "[\s]|,|-|\/|[0-9]") | Where-Object {$_ -ne '.'}
                                if ($UnexpectedCharsCheck.Count -gt 0) {
                                    $Session:SearchRemoteHosts = $False
                                    Sync-UDElement -Id "SearchRemoteHosts"
                                    $Msg = "The following invalid characters were found in the 'IPAddress' field:`n$($UnexpectedCharsCheck -join ', ')"
                                    Show-UDToast -Message $Msg -Position 'topRight' -Title "BadChars" -Duration 10000
                                    Write-Error $Msg
                                    return
                                }
    
                                if (!$($IPAddresses -match [regex]::Escape(',')) -and !$($IPAddresses -match [regex]::Escape('-')) -and !$($IPAddresses -match [regex]::Escape('/'))) {
                                    $null = $RemoteHostListPrep.Add($IPAddresses.Trim())
                                }
                                if ($IPAddresses -match [regex]::Escape(',')) {
                                    $ArrayOfRanges = $IPAddresses -split [regex]::Escape(',') | foreach {
                                        if (![System.String]::IsNullOrWhiteSpace($_)) {
                                            $_.Trim()
                                        }
                                    }
    
                                    if ($IPAddresses -match [regex]::Escape('-') -and $IPAddresses -match [regex]::Escape('/')) {
                                        foreach ($IPRange in $ArrayOfRanges) {
                                            if ($IPRange -match [regex]::Escape('-')) {
                                                $StartIP = $($IPRange -split [regex]::Escape('-'))[0]
                                                $EndIP = $($IPRange -split [regex]::Escape('-'))[-1]
    
                                                if (!$(TestIsValidIPAddress -IPAddress $StartIP)) {
                                                    Show-UDToast -Message "$StartIP is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadStartIP" -Duration 5000
                                                }
                                                if (!$(TestIsValidIPAddress -IPAddress $EndIP)) {
                                                    Show-UDToast -Message "$EndIP is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadEndIP" -Duration 5000
                                                }
                                                if (!$(TestIsValidIPAddress -IPAddress $StartIP) -or !$(TestIsValidIPAddress -IPAddress $EndIP)) {
                                                    continue
                                                }
    
                                                Get-IPRange -start $StartIP -end $EndIP | foreach {
                                                    $null = $RemoteHostListPrep.Add($_)
                                                }
                                            }
                                            if ($IPRange -match [regex]::Escape('/')) {
                                                $IPAddr = $($IPRange -split [regex]::Escape('/'))[0]
                                                $CIDRInt = $($IPRange -split [regex]::Escape('/'))[-1]
    
                                                Get-IPRange -ip $IPAddr -cidr $CIDRInt | foreach {
                                                    $null = $RemoteHostListPrep.Add($_)
                                                }
                                            }
                                        }
                                    }
                                    if ($IPAddresses -match [regex]::Escape('-') -and !$($IPAddresses -match [regex]::Escape('/'))) {
                                        foreach ($IPRange in $ArrayOfRanges) {
                                            $StartIP = $($IPRange -split [regex]::Escape('-'))[0]
                                            $EndIP = $($IPRange -split [regex]::Escape('-'))[-1]
    
                                            if (!$(TestIsValidIPAddress -IPAddress $StartIP)) {
                                                Show-UDToast -Message "$StartIP is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadStartIP" -Duration 5000
                                            }
                                            if (!$(TestIsValidIPAddress -IPAddress $EndIP)) {
                                                Show-UDToast -Message "$EndIP is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadEndIP" -Duration 5000
                                            }
                                            if (!$(TestIsValidIPAddress -IPAddress $StartIP) -or !$(TestIsValidIPAddress -IPAddress $EndIP)) {
                                                continue
                                            }
    
                                            Get-IPRange -start $StartIP -end $EndIP | foreach {
                                                $null = $RemoteHostListPrep.Add($_)
                                            }
                                        }
                                    }
                                    if ($IPAddresses -match [regex]::Escape('/') -and !$($IPAddresses -match [regex]::Escape('-'))) {
                                        foreach ($IPRange in $ArrayOfRanges) {
                                            $IPAddr = $($IPRange -split [regex]::Escape('/'))[0]
                                            $CIDRInt = $($IPRange -split [regex]::Escape('/'))[-1]
    
                                            Get-IPRange -ip $IPAddr -cidr $CIDRInt | foreach {
                                                $null = $RemoteHostListPrep.Add($_)
                                            }
                                        }
                                    }
                                    if (!$($IPAddresses -match [regex]::Escape('/')) -and !$($IPAddresses -match [regex]::Escape('-'))) {
                                        $IPAddresses -split [regex]::Escape(',') | foreach {
                                            if (!$(TestIsValidIPAddress -IPAddress $_)) {
                                                Show-UDToast -Message "$_ is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadIP" -Duration 5000
                                            }
                                            else {
                                                $null = $RemoteHostListPrep.Add($_.Trim())
                                            }
                                        }
                                    }
                                }
                                if ($IPAddresses -match [regex]::Escape('-') -and $IPAddresses -match [regex]::Escape('/')) { 
                                    Write-Error "You are either missing a comma between two or more separate IP Ranges, or your notation is incorrect. Please try again."
                                    $global:FunctionResult = "1"
                                    return
                                }
                                if ($IPAddresses -match [regex]::Escape('-') -and !$($IPAddresses -match [regex]::Escape('/'))) {
                                    $StartIP = $($IPRange -split [regex]::Escape('-'))[0]
                                    $EndIP = $($IPRange -split [regex]::Escape('-'))[-1]
    
                                    if (!$(TestIsValidIPAddress -IPAddress $StartIP)) {
                                        Show-UDToast -Message "$StartIP is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadStartIP" -Duration 5000
                                    }
                                    if (!$(TestIsValidIPAddress -IPAddress $EndIP)) {
                                        Show-UDToast -Message "$EndIP is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadEndIP" -Duration 5000
                                    }
                                    if (!$(TestIsValidIPAddress -IPAddress $StartIP) -or !$(TestIsValidIPAddress -IPAddress $EndIP)) {
                                        continue
                                    }
    
                                    Get-IPRange -start $StartIP -end $EndIP | foreach {
                                        $null = $RemoteHostListPrep.Add($_)
                                    }
                                    
                                }
                                if ($IPAddresses -match [regex]::Escape('/') -and !$($IPAddresses -match [regex]::Escape('-'))) {
                                    $IPAddr = $($IPRange -split [regex]::Escape('/'))[0]
                                    $CIDRInt = $($IPRange -split [regex]::Escape('/'))[-1]
    
                                    Get-IPRange -ip $IPAddr -cidr $CIDRInt | foreach {
                                        $null = $RemoteHostListPrep.Add($_)
                                    }
                                }
                            }
    
                            # Filter Out the Remote Hosts that we can't resolve via DNS
                            [System.Collections.ArrayList]$RemoteHostList = @()
    
                            $null = Clear-DnsClientCache
                            foreach ($HNameOrIP in $RemoteHostListPrep) {
                                try {
                                    $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $HNameOrIP -ErrorAction Stop
    
                                    if ($RemoteHostNetworkInfo.HostName -eq "localhost") {
                                        $HostNameOutput = hostname
                                        $HostNameShort = if ($HostNameOutput -match "\.") {$($HostNameOutput -split "\.")[0]} else {$HostNameOutput}
                                        [System.Collections.ArrayList][array]$IPAddresses = Get-NetworkInfo -InterfaceStatus Up -AddressFamily IPv4 | foreach {$_.Address.IPAddressToString}
                        
                                        $RemoteHostNetworkInfo.FQDN = $HostNameOutput
                                        $RemoteHostNetworkInfo.HostName = $HostNameShort
                                        $RemoteHostNetworkInfo.IPAddressList = $IPAddresses
                                        $RemoteHostNetworkInfo.Domain = GetDomainName
                                    }
    
                                    # ResolveHost will NOT throw an error even if it can't figure out HostName, Domain, or FQDN as long as $IPAddr IS pingable
                                    # So, we need to do the below to compensate for code downstream that relies on HostName, Domain, and FQDN
                                    if (!$RemoteHostNetworkInfo.HostName) {
                                        $IPAddr = $RemoteHostNetworkInfo.IPAddressList[0]
                                        $LastTwoOctets = $($IPAddr -split '\.')[2..3] -join 'Dot'
                                        $UpdatedHostName = NewUniqueString -PossibleNewUniqueString "Unknown$LastTwoOctets" -ArrayOfStrings $PUDRSSyncHT.RemoteHostList.HostName
                                        $RemoteHostNetworkInfo.HostName = $UpdatedHostName
                                        $RemoteHostNetworkInfo.FQDN = $UpdatedHostName + '.Unknown'
                                        $RemoteHostNetworkInfo.Domain = 'Unknown'
                                    }
    
                                    $null = $RemoteHostList.Add($RemoteHostNetworkInfo)
                                }
                                catch {
                                    Show-UDToast -Message $_.Exception.Message -Duration 5000
                                    Show-UDToast -Message "Unable to resolve $HNameOrIP" -Position 'topRight' -Title "CheckDNS" -Duration 5000
                                    continue
                                }
                            }
                            $PUDRSSyncHT.RemoteHostList = $RemoteHostList
    
                            # Add Keys for each of the Remote Hosts in the $InitialRemoteHostList    
                            foreach ($RHost in $RemoteHostList) {
                                if ($PUDRSSyncHT.Keys -notcontains "$($RHost.HostName)Info") {
                                    $Key = $RHost.HostName + "Info"
                                    $Value = @{
                                        NetworkInfo                 = $RHost
                                        CredHT                      = $null
                                        ServerInventoryStatic       = $null
                                        RelevantNetworkInterfaces   = $null
                                        LiveDataRSInfo              = $null
                                        LiveDataTracker             = @{Current = $null; Previous = $null}
                                    }
                                    foreach ($DynPage in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                        $DynPageHT = @{
                                            LiveDataRSInfo      = $null
                                            LiveDataTracker     = @{Current = $null; Previous = $null}
                                        }
                                        $Value.Add($($DynPage -replace "[\s]",""),$DynPageHT)
                                    }
                                    $PUDRSSyncHT.Add($Key,$Value)
                                }
                            }
    
                            $Session:SearchRemoteHosts = $True
                            Sync-UDElement -Id "SearchRemoteHosts"
    
                            # Refresh the Main Content
                            Sync-UDElement -Id "MainContent"
                        }
                    }
                }
            }
        }
    
        <#
        New-UDRow -Endpoint {
            New-UDColumn -Endpoint {
                New-UDHeading -Text "Sampling of Available Remote Hosts" -Size 5
            }
        }
        #>
    
        New-UDElement -Id "MainContent" -Tag div -EndPoint {
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Endpoint {
                    $RHostUDTableEndpoint = {
                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                        $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                        $RHost = $PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RHostName}
    
                        $RHostTableData = @{}
                        $RHostTableData.Add("HostName",$RHost.HostName.ToUpper())
                        $RHostTableData.Add("FQDN",$RHost.FQDN)
    
                        # Guess Operating System
                        if ($RHost.HostName -eq $env:ComputerName) {
                            $OSGuess = $(Get-CimInstance Win32_OperatingSystem).Caption
                        }
                        else {
                            if ([bool]$(Get-Command nmap -ErrorAction SilentlyContinue)) {
                                $NmapOSResult = nmap -O $RHost.IPAddressList[0]
                                if ($NmapOSResult -match "OS details:") {
                                    $OSGuessPrep = $($NmapOSResult | Where-Object {$_ -match "OS details:"}) -replace "OS details: ",""
                                    $OSGuess = if ($OSGuessPrep -match ',') {$($OSGuessPrep -split ',')[0].Trim()} else {$OSGuessPrep.Trim()}
                                }
                                if ($NmapOSResult -match "Aggressive OS guesses:") {
                                    $OSGuessPrep = $($NmapOSResult | Where-Object {$_ -match "Aggressive OS guesses:"}) -replace "Aggressive OS guesses: ",""
                                    $OSGuessPrep = if ($OSGuessPrep -match ',') {$($OSGuessPrep -split ',')[0]} else {$OSGuessPrep}
                                    $OSGuess = $($OSGuessPrep -replace "[\s]\([0-9]+%\)","").Trim()
                                }
                                if (!$OSGuess) {
                                    $OSGuess = $null
                                }
                            }
                            else {
                                $OSGuess = $null
                            }
                        }
                        $RHostTableData.Add("OS_Guess",$OSGuess)
    
                        $IPAddressListAsString = @($RHost.IPAddressList) -join ", "
                        $RHostTableData.Add("IPAddress",$IPAddressListAsString)
    
                        # Check Ping
                        try {
                            $PingResult =  [System.Net.NetworkInformation.Ping]::new().Send(
                                $RHost.IPAddressList[0],1000
                            ) | Select-Object -Property Address,Status,RoundtripTime -ExcludeProperty PSComputerName,PSShowComputerName,RunspaceId
    
                            $PingStatus = if ($PingResult.Status.ToString() -eq "Success") {"Available"} else {"Unavailable"}
                            $RHostTableData.Add("PingStatus",$PingStatus)
                        }
                        catch {
                            $RHostTableData.Add("PingStatus","Unavailable")
                        }
    
                        # Check WSMan Ports
                        try {
                            $WSMan5985Url = "http://$($RHost.IPAddressList[0])`:5985/wsman"
                            $WSMan5986Url = "http://$($RHost.IPAddressList[0])`:5986/wsman"
                            $WSManUrls = @($WSMan5985Url,$WSMan5986Url)
                            foreach ($WSManUrl in $WSManUrls) {
                                $Request = [System.Net.WebRequest]::Create($WSManUrl)
                                $Request.Timeout = 1000
                                try {
                                    [System.Net.WebResponse]$Response = $Request.GetResponse()
                                }
                                catch {
                                    if ($_.Exception.Message -match "The remote server returned an error: \(405\)") {
                                        if ($WSManUrl -match "5985") {
                                            $WSMan5985Available = $True
                                        }
                                        else {
                                            $WSMan5986Available = $True
                                        }
                                    }
                                    elseif ($_.Exception.Message -match "The operation has timed out") {
                                        if ($WSManUrl -match "5985") {
                                            $WSMan5985Available = $False
                                        }
                                        else {
                                            $WSMan5986Available = $False
                                        }
                                    }
                                    else {
                                        if ($WSManUrl -match "5985") {
                                            $WSMan5985Available = $False
                                        }
                                        else {
                                            $WSMan5986Available = $False
                                        }
                                    }
                                }
                            }
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $RHostTableData.Add("WSMan","Available")
    
                                [System.Collections.ArrayList]$WSManPorts = @()
                                if ($WSMan5985Available) {
                                    $null = $WSManPorts.Add("5985")
                                }
                                if ($WSMan5986Available) {
                                    $null = $WSManPorts.Add("5986")
                                }
    
                                $WSManPortsString = $WSManPorts -join ', '
                                $RHostTableData.Add("WSManPorts",$WSManPortsString)
                            }
                        }
                        catch {
                            $RHostTableData.Add("WSMan","Unavailable")
                        }
    
                        # Check SSH
                        try {
                            $TestSSHResult = TestPort -HostName $RHost.IPAddressList[0] -Port 22
    
                            if ($TestSSHResult.Open) {
                                $RHostTableData.Add("SSH","Available")
                            }
                            else {
                                $RHostTableData.Add("SSH","Unavailable")
                            }
                        }
                        catch {
                            $RHostTableData.Add("SSH","Unavailable")
                        }
    
                        $RHostTableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                        if ($RHostTableData.WSMan -eq "Available" -or $RHostTableData.SSH -eq "Available") {
                            # We are within an -Endpoint, so $Session: variables should be available
                            #if ($PUDRSSyncHT."$($RHost.HostName)`Info".CredHT.PSRemotingCreds -ne $null) {
                            if ($Session:CredentialHT.$($RHost.HostName).PSRemotingCreds -ne $null) {
                                $RHostTableData.Add("ManageLink",$(New-UDLink -Text "Manage" -Url "/ToolSelect/$($RHost.HostName)"))
                            }
                            else {
                                $RHostTableData.Add("ManageLink",$(New-UDLink -Text "Manage" -Url "/PSRemotingCreds/$($RHost.HostName)"))
                            }
                        }
                        else {
                            $RHostTableData.Add("ManageLink","Unavailable")
                        }
    
                        $RHostTableData.Add("NewCreds",$(New-UDLink -Text "NewCreds" -Url "/PSRemotingCreds/$($RHost.HostName)"))
    
                        if ($PUDRSSyncHT."$($RHost.HostName)Info".Keys -contains "RHostTableData") {
                            $PUDRSSyncHT."$($RHost.HostName)Info".RHostTableData = $RHostTableData
                        }
                        else {
                            $PUDRSSyncHT."$($RHost.HostName)Info".Add("RHostTableData",$RHostTableData)
                        }
                        
                        [pscustomobject]$RHostTableData | Out-UDTableData -Property @("HostName","FQDN","OS_Guess","IPAddress","PingStatus","WSMan","WSManPorts","SSH","DateTime","ManageLink","NewCreds")
                    }
                    $RHostUDTableEndpointAsString = $RHostUDTableEndpoint.ToString()
    
                    $RHostCounter = 0
                    #$Session:CredentialHT = @{}
                    foreach ($RHost in $PUDRSSyncHT.RemoteHostList) {
                        $RHostUDTableEndpoint = [scriptblock]::Create(
                            $(
                                "`$RHostName = '$($RHost.HostName)'" + "`n" +
                                $RHostUDTableEndpointAsString
                            )
                        )
    
                        $ResultProperties = @("HostName","FQDN","OS_Guess","IPAddress","PingStatus","WSMan","WSManPorts","SSH","DateTime","ManageLink","NewCreds")
                        $RHostUDTableSplatParams = @{
                            Title           = $RHost.HostName.ToUpper()
                            Headers         = $ResultProperties
                            #AutoRefresh     = $True 
                            #RefreshInterval = 15
                            Endpoint        = $RHostUDTableEndpoint
                        }
                        New-UDTable @RHostUDTableSplatParams
    
                        $RHostCounter++
    
                        if ($RHostCounter -ge $($PUDRSSyncHT.RemoteHostList.Count-1)) {
                            New-UDColumn -Endpoint {
                                $Session:HomePageLoadingTracker = $True
                                $Session:SearchRemoteHosts = $False
                                Sync-UDElement -Id "SearchRemoteHosts"
                            }
                        }
                    }
    
                    # This hidden column refreshes the RemoteHostList so that when the HomePage is reloaded, it only displays
                    # host/devices that can be resolved. This is so that if PUDAdminCenter is used to shutdown/restart a Remote Host,
                    # the list of hosts on the HomePage is accurate 
                    New-UDColumn -AutoRefresh -RefreshInterval 10 -Endpoint {
                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                        $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                        if ($Cache:HomeFinishedLoading -and !$Cache:RHostRefreshAlreadyRan) {
                            $null = Clear-DnsClientCache
                            foreach ($IPAddr in $PUDRSSyncHT.RemoteHostList.IPAddressList) {
                                try {
                                    $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $IPAddr -ErrorAction Stop
    
                                    if ($RemoteHostNetworkInfo.HostName -eq "localhost") {
                                        $HostNameOutput = hostname
                                        $HostNameShort = if ($HostNameOutput -match "\.") {$($HostNameOutput -split "\.")[0]} else {$HostNameOutput}
                                        [System.Collections.ArrayList][array]$IPAddresses = Get-NetworkInfo -InterfaceStatus Up -AddressFamily IPv4 | foreach {$_.Address.IPAddressToString}
                        
                                        $RemoteHostNetworkInfo.FQDN = $HostNameOutput
                                        $RemoteHostNetworkInfo.HostName = $HostNameShort
                                        $RemoteHostNetworkInfo.IPAddressList = $IPAddresses
                                        $RemoteHostNetworkInfo.Domain = GetDomainName
                                    }
    
                                    # ResolveHost will NOT throw an error even if it can't figure out HostName, Domain, or FQDN as long as $IPAddr IS pingable
                                    # So, we need to do the below to compensate for code downstream that relies on HostName, Domain, and FQDN
                                    if (!$RemoteHostNetworkInfo.HostName) {
                                        $LastTwoOctets = $($IPAddr -split '\.')[2..3] -join 'Dot'
                                        $UpdatedHostName = NewUniqueString -PossibleNewUniqueString "Unknown$LastTwoOctets" -ArrayOfStrings $PUDRSSyncHT.RemoteHostList.HostName
                                        $RemoteHostNetworkInfo.HostName = $UpdatedHostName
                                        $RemoteHostNetworkInfo.FQDN = $UpdatedHostName + '.Unknown'
                                        $RemoteHostNetworkInfo.Domain = 'Unknown'
                                    }
    
                                    $null = $RemoteHostList.Add($RemoteHostNetworkInfo)
                                }
                                catch {
                                    continue
                                }
                            }
                            $PUDRSSyncHT.RemoteHostList = $RemoteHostList
    
                            $Cache:RHostRefreshAlreadyRan = $True
                        }
                    }
                }
            }
        }
    
        #endregion >> HomePage Main Content
    }
    # IMPORTANT NOTE: Anytime New-UDPage is used with parameter set '-Name -Content', it appears in the hamburger menu
    # This is REQUIRED for the HomePage, otherwise http://localhost won't load (in otherwords, you can't use the
    # parameter set '-Url -Endpoint' for the HomePage).
    # Also, it is important that the HomePage comes first in the $Pages ArrayList
    $HomePage = New-UDPage -Name "Home" -Icon home -Content $HomePageContent
    $null = $Pages.Insert(0,$HomePage)
    

    #endregion >> Static Pages
    
    # Finalize the Site
    $Theme = New-UDTheme -Name "DefaultEx" -Parent Default -Definition @{
        UDDashboard = @{
            BackgroundColor = "rgb(255,255,255)"
        }
    }
    $MyDashboard = New-UDDashboard -Title "PUD Admin Center" -Pages $Pages -Theme $Theme

    # Start the Site
    Start-UDDashboard -Dashboard $MyDashboard -Port $Port
}


<#
    
    .SYNOPSIS
        Return subkeys based on the path.
    
    .DESCRIPTION
        Return subkeys based on the path. The supported Operating Systems are
        Window Server 2012 and Windows Server 2012R2 and Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers

    .PARAMETER path
        This parameter is MANDATORY.

        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-RegistrySubkeys -path "HKLM:\SOFTWARE\OpenSSH"
    
#>
function Get-RegistrySubKeys {
    Param([Parameter(Mandatory = $true)][string]$path)
    
    $ErrorActionPreference = "Stop"
    
    $Error.Clear()
    $keyArray = @()
    $key = Get-Item $path
    foreach ($sub in $key.GetSubKeyNames() | Sort-Object)
    {
        $keyEntry = New-Object System.Object
        $keyEntry | Add-Member -type NoteProperty -name Name -value $sub  
        $subKeyPath = $key.PSPath+'\'+$sub
        $keyEntry | Add-Member -type NoteProperty -name Path -value $subKeyPath
        $keyEntry | Add-Member -type NoteProperty -name childCount -value @( Get-ChildItem $subKeyPath -ErrorAction SilentlyContinue ).Length
        $keyArray += $keyEntry
    }
    $keyArray
    
}


<#
    
    .SYNOPSIS
        Return values based on the key path.
    
    .DESCRIPTION
        Return values based on the key path. The supported Operating Systems are
        Window Server 2012 and Windows Server 2012R2 and Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers

    .PARAMETER path
        This parameter is OPTIONAL.

        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-RegistryValues -path "HKLM:\SOFTWARE\OpenSSH"
    
#>
function Get-RegistryValues {
    Param([string]$path)
    
    $ErrorActionPreference = "Stop"
    
    $Error.Clear()
    $valueArray = @()
    $values = Get-Item  -path $path
    foreach ($val in $values.Property)
      {
        $valueEntry = New-Object System.Object
    
    
        if ($val -eq '(default)'){
            $valueEntry | Add-Member -type NoteProperty -name Name -value $val
            $valueEntry | Add-Member -type NoteProperty -name type -value $values.GetValueKind('')
            $valueEntry | Add-Member -type NoteProperty -name data -value (get-itemproperty -literalpath $path).'(default)'
            }
        else{
            $valueEntry | Add-Member -type NoteProperty -name Name -value $val 
            $valueEntry | Add-Member -type NoteProperty -name type -value $values.GetValueKind($val)
            $valueEntry | Add-Member -type NoteProperty -name data -value $values.GetValue($val)
        }
    
        $valueArray += $valueEntry
      }
      $valueArray    
}


<#
    
    .SYNOPSIS
        Gets a computer's remote desktop settings.
    
    .DESCRIPTION
        Gets a computer's remote desktop settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-RemoteDesktop
    
#>
function Get-RemoteDesktop {
    function Get-DenyTSConnectionsValue {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        
        $exists = Get-ItemProperty -Path $key -Name fDenyTSConnections -ErrorAction SilentlyContinue
        if ($exists)
        {
            $keyValue = $exists.fDenyTSConnections
            return $keyValue -ne 1
        }
    
        Write-Error "The value for key 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' was not found."
    }
    
    function Get-UserAuthenticationValue {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    
        $exists = Get-ItemProperty -Path $key -Name UserAuthentication -ErrorAction SilentlyContinue
        if ($exists)
        {
            $keyValue = $exists.UserAuthentication
            return $keyValue -eq 1
        }
    
        Write-Error "The value for key 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' was not found."
    }
    
    function Get-RemoteAppSetting {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        
        $exists = Get-ItemProperty -Path $key -Name EnableRemoteApp -ErrorAction SilentlyContinue
        if ($exists)
        {
            $keyValue = $exists.EnableRemoteApp
            return $keyValue -eq 1
    
        } else {
            return $false;
        }
    }
    
    $denyValue = Get-DenyTSConnectionsValue;
    $nla = Get-UserAuthenticationValue;
    $remoteApp = Get-RemoteAppSetting;
    
    $result = New-Object -TypeName PSObject
    $result | Add-Member -MemberType NoteProperty -Name "allowRemoteDesktop" $denyValue;
    $result | Add-Member -MemberType NoteProperty -Name "allowRemoteDesktopWithNLA" $nla;
    $result | Add-Member -MemberType NoteProperty -Name "enableRemoteApp" $remoteApp;
    $result
}


<#
    
    .SYNOPSIS
        Script to get list of scheduled tasks.
    
    .DESCRIPTION
        Script to get list of scheduled tasks.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers

    .PARAMETER taskPath
        This parameter is OPTIONAL.

        TODO

    .PARAMETER taskName
        This parameter is OPTIONAL.

        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-ScheduledTasks
    
#>
function Get-ScheduledTasks {
    param (
      [Parameter(Mandatory = $false)]
      [String]
      $taskPath,
    
      [Parameter(Mandatory = $false)]
      [String]
      $taskName
    )
    
    Import-Module ScheduledTasks
    
    function New-TaskWrapper
    {
      param (
        [Parameter(Mandatory = $true, ValueFromPipeline=$true)]
        $task
      )
    
      $task | Add-Member -MemberType NoteProperty -Name 'status' -Value $task.state.ToString()
      $info = Get-ScheduledTaskInfo $task
    
      $triggerCopies = @()
      for ($i=0;$i -lt $task.Triggers.Length;$i++)
      {
        $trigger = $task.Triggers[$i];
        $triggerCopy = $trigger.PSObject.Copy();
        if ($trigger -ne $null) {
            if ($trigger.StartBoundary -eq $null -or$trigger.StartBoundary -eq '') 
            {
                $startDate = $null;
            }
            else 
            {
                $startDate = [datetime]($trigger.StartBoundary)
            }
          
            $triggerCopy | Add-Member -MemberType NoteProperty -Name 'TriggerAtDate' -Value $startDate -TypeName System.DateTime
    
            if ($trigger.EndBoundary -eq $null -or$trigger.EndBoundary -eq '') 
            {
                $endDate = $null;
            }
            else 
            {
                $endDate = [datetime]($trigger.EndBoundary)
            }
            
            $triggerCopy | Add-Member -MemberType NoteProperty -Name 'TriggerEndDate' -Value $endDate -TypeName System.DateTime
    
            $triggerCopies += $triggerCopy
        }
    
      }
    
      $task | Add-Member -MemberType NoteProperty -Name 'TriggersEx' -Value $triggerCopies
    
      New-Object -TypeName PSObject -Property @{
          
          ScheduledTask = $task
          ScheduledTaskInfo = $info
      }
    }
    
    if ($taskPath -and $taskName) {
      try
      {
        $task = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
        New-TaskWrapper $task
      }
      catch
      {
      }
    } else {
        Get-ScheduledTask | ForEach-Object {
          New-TaskWrapper $_
        }
    }
    
}


<#
    .SYNOPSIS
        Retrieves the inventory data for a server.
    
    .DESCRIPTION
        Retrieves the inventory data for a server.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-ServerInventory
#>
function Get-ServerInventory {
    Set-StrictMode -Version 5.0
    
    import-module CimCmdlets
    
    <#
        .SYNOPSIS
        Converts an arbitrary version string into just 'Major.Minor'
        
        .DESCRIPTION
        To make OS version comparisons we only want to compare the major and 
        minor version.  Build number and/os CSD are not interesting.
    #>
    function convertOsVersion([string] $osVersion) {
        try {
            $version = New-Object Version $osVersion -ErrorAction Stop
    
            if ($version -and $version.Major -ne -1 -and $version.Minor -ne -1) {
                $versionString = "{0}.{1}" -f $version.Major, $version.Minor
    
                return New-Object Version $versionString
            }
        }
        catch {
            # The version string is not in the correct format
            return $null
        }
    }
    
    <#
        .SYNOPSIS
        Determines if CredSSP is enabled for the current server or client.
        
        .DESCRIPTION
        Check the registry value for the CredSSP enabled state.
    #>
    function isCredSSPEnabled() {
        $CredSsp = Get-Item WSMan:\localhost\Service\Auth\CredSSP -ErrorAction SilentlyContinue
        if ($CredSSp) {
            return [System.Convert]::ToBoolean($CredSsp.Value)
        }
    
        return $false
    }
    
    <#
        .SYNOPSIS
        Determines if the Hyper-V role is installed for the current server or client.
        
        .DESCRIPTION
        The Hyper-V role is installed when the VMMS service is available.  This is much
        faster then checking Get-WindowsFeature and works on Windows Client SKUs.
    #>
    function isHyperVRoleInstalled() {
        $vmmsService = Get-Service -Name "VMMS" -ErrorAction SilentlyContinue
    
        return $vmmsService -and $vmmsService.Name -eq "VMMS"
    }
    
    <#
        .SYNOPSIS
        Determines if the Hyper-V PowerShell support module is installed for the current server or client.
        
        .DESCRIPTION
        The Hyper-V PowerShell support module is installed when the modules cmdlets are available.  This is much
        faster then checking Get-WindowsFeature and works on Windows Client SKUs.
    #>
    function isHyperVPowerShellSupportInstalled() {
        # quicker way to find the module existence. it doesn't load the module.
        return !!(Get-Module -ListAvailable Hyper-V -ErrorAction SilentlyContinue)
    }
    
    <#
        .SYNOPSIS
        Determines if Windows Management Framework (WMF) 5.0, or higher, is installed for the current server or client.
        
        .DESCRIPTION
        Windows Admin Center requires WMF 5 so check the registey for WMF version on Windows versions that are less than
        Windows Server 2016.
    #>
    function isWMF5Installed([string] $operatingSystemVersion) {
        Set-Variable Server2016 -Option Constant -Value (New-Object Version '10.0')   # And Windows 10 client SKUs
        Set-Variable Server2012 -Option Constant -Value (New-Object Version '6.2')
    
        $version = convertOsVersion $operatingSystemVersion
        if ($version -eq $null) {
            return $false        # Since the OS version string is not properly formatted we cannot know the true installed state.
        }
        
        if ($version -ge $Server2016) {
            # It's okay to assume that 2016 and up comes with WMF 5 or higher installed
            return $true
        } else {
            if ($version -ge $Server2012) {
                # Windows 2012/2012R2 are supported as long as WMF 5 or higher is installed
                $registryKey = 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine'
                $registryKeyValue = Get-ItemProperty -Path $registryKey -Name PowerShellVersion -ErrorAction SilentlyContinue
        
                if ($registryKeyValue -and ($registryKeyValue.PowerShellVersion.Length -ne 0)) {
                    $installedWmfVersion = [Version]$registryKeyValue.PowerShellVersion
        
                    if ($installedWmfVersion -ge [Version]'5.0') {
                        return $true
                    }
                }
            }
        }
        
        return $false
    }
    
    <#
        .SYNOPSIS
        Determines if the current usser is a system administrator of the current server or client.
        
        .DESCRIPTION
        Determines if the current usser is a system administrator of the current server or client.
    #>
    function isUserAnAdministrator() {
        return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    }
    
    <#
        .SYNOPSIS
        Determines if the current server supports Failover Clusters Time Series Database.
        
        .DESCRIPTION
        Use the existance of the cluster cmdlet Get-ClusterPerformanceHistory to determine if TSDB 
        is supported or not.
    #>
    function getClusterPerformanceHistoryCmdLet($failoverClusters) {
        return $failoverClusters.ExportedCommands.ContainsKey("Get-ClusterPerformanceHistory")
    }
    
    <#
        .SYNOPSIS
        Get some basic information about the Failover Cluster that is running on this server.
        
        .DESCRIPTION
        Create a basic inventory of the Failover Cluster that may be running in this server.
    #>
    function getClusterInformation() {
        # JEA code requires to pre-import the module (this is slow on failover cluster environment.)
        Import-Module FailoverClusters -ErrorAction SilentlyContinue
    
        $returnValues = @{}
    
        $returnValues.IsTsdbEnabled = $false
        $returnValues.IsCluster = $false
        $returnValues.ClusterFqdn = $null
    
        $failoverClusters = Get-Module FailoverClusters -ErrorAction SilentlyContinue
        if ($failoverClusters) {
            $returnValues.IsTsdbEnabled = getClusterPerformanceHistoryCmdLet $failoverClusters
        }
    
        $namespace = Get-CimInstance -Namespace root/MSCluster -ClassName __NAMESPACE -ErrorAction SilentlyContinue
        if ($namespace) {
            $cluster = Get-CimInstance -Namespace root/MSCluster -Query "Select fqdn from MSCluster_Cluster" -ErrorAction SilentlyContinue
            if ($cluster) {
                $returnValues.IsCluster = $true
                $returnValues.ClusterFqdn = $cluster.fqdn
            }
        }
        
        return $returnValues
    }
    
    <#
        .SYNOPSIS
        Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the passed in computer name.
        
        .DESCRIPTION
        Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the passed in computer name.
    #>
    function getComputerFqdn($computerName) {
        return ([System.Net.Dns]::GetHostEntry($computerName)).HostName
    }
    
    <#
        .SYNOPSIS
        Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the current server or client.
        
        .DESCRIPTION
        Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the current server or client.
    #>
    function getHostFqdn($computerSystem) {
        $computerName = $computerSystem.DNSHostName
        if ($computerName -eq $null) {
            $computerName = $computerSystem.Name
        }
    
        return getComputerFqdn $computerName
    }
    
    <#
        .SYNOPSIS
        Are the needed management CIM interfaces available on the current server or client.
        
        .DESCRIPTION
        Check for the presence of the required server management CIM interfaces.
    #>
    function getManagementToolsSupportInformation() {
        $returnValues = @{}
    
        $returnValues.ManagementToolsAvailable = $false
        $returnValues.ServerManagerAvailable = $false
    
        $namespaces = Get-CimInstance -Namespace root/microsoft/windows -ClassName __NAMESPACE -ErrorAction SilentlyContinue
    
        if ($namespaces) {
            $returnValues.ManagementToolsAvailable = ($namespaces | Where-Object { $_.Name -ieq "ManagementTools" }) -ne $null
            $returnValues.ServerManagerAvailable = ($namespaces | Where-Object { $_.Name -ieq "ServerManager" }) -ne $null
        }
    
        return $returnValues
    }
    
    <#
        .SYNOPSIS
        Check the remote app enabled or not.
        
        .DESCRIPTION
        Check the remote app enabled or not.
    #>
    function isRemoteAppEnabled() {
        Set-Variable key -Option Constant -Value "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
        Set-Variable enableRemoteAppPropertyName -Option Constant -Value "EnableRemoteApp"
    
        $registryKeyValue = Get-ItemProperty -Path $key -Name EnableRemoteApp -ErrorAction SilentlyContinue
        
        return $registryKeyValue -and ($registryKeyValue.PSObject.Properties.Name -match $enableRemoteAppPropertyName)
    }
    
    <#
        .SYNOPSIS
        Check the remote app enabled or not.
        
        .DESCRIPTION
        Check the remote app enabled or not.
    #>
    
    <#
        .SYNOPSIS
        Get the Win32_OperatingSystem information
        
        .DESCRIPTION
        Get the Win32_OperatingSystem instance and filter the results to just the required properties.
        This filtering will make the response payload much smaller.
    #>
    function getOperatingSystemInfo() {
        return Get-CimInstance Win32_OperatingSystem | Microsoft.PowerShell.Utility\Select-Object csName, Caption, OperatingSystemSKU, Version, ProductType
    }
    
    <#
        .SYNOPSIS
        Get the Win32_ComputerSystem information
        
        .DESCRIPTION
        Get the Win32_ComputerSystem instance and filter the results to just the required properties.
        This filtering will make the response payload much smaller.
    #>
    function getComputerSystemInfo() {
        return Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | `
            Microsoft.PowerShell.Utility\Select-Object TotalPhysicalMemory, DomainRole, Manufacturer, Model, NumberOfLogicalProcessors, Domain, Workgroup, DNSHostName, Name, PartOfDomain
    }
    
    ###########################################################################
    # main()
    ###########################################################################
    
    $operatingSystem = getOperatingSystemInfo
    $computerSystem = getComputerSystemInfo
    $isAdministrator = isUserAnAdministrator
    $fqdn = getHostFqdn $computerSystem
    $managementToolsInformation = getManagementToolsSupportInformation
    $isWmfInstalled = isWMF5Installed $operatingSystem.Version
    $clusterInformation = getClusterInformation -ErrorAction SilentlyContinue
    $isHyperVPowershellInstalled = isHyperVPowerShellSupportInstalled
    $isHyperVRoleInstalled = isHyperVRoleInstalled
    $isCredSSPEnabled = isCredSSPEnabled
    $isRemoteAppEnabled = isRemoteAppEnabled
    
    $result = New-Object PSObject
    
    $result | Add-Member -MemberType NoteProperty -Name 'IsAdministrator' -Value $isAdministrator
    $result | Add-Member -MemberType NoteProperty -Name 'OperatingSystem' -Value $operatingSystem
    $result | Add-Member -MemberType NoteProperty -Name 'ComputerSystem' -Value $computerSystem
    $result | Add-Member -MemberType NoteProperty -Name 'Fqdn' -Value $fqdn
    $result | Add-Member -MemberType NoteProperty -Name 'IsManagementToolsAvailable' -Value $managementToolsInformation.ManagementToolsAvailable
    $result | Add-Member -MemberType NoteProperty -Name 'IsServerManagerAvailable' -Value $managementToolsInformation.ServerManagerAvailable
    $result | Add-Member -MemberType NoteProperty -Name 'IsCluster' -Value $clusterInformation.IsCluster
    $result | Add-Member -MemberType NoteProperty -Name 'ClusterFqdn' -Value $clusterInformation.ClusterFqdn
    $result | Add-Member -MemberType NoteProperty -Name 'IsWmfInstalled' -Value $isWmfInstalled
    $result | Add-Member -MemberType NoteProperty -Name 'IsTsdbEnabled' -Value $clusterInformation.IsTsdbEnabled
    $result | Add-Member -MemberType NoteProperty -Name 'IsHyperVRoleInstalled' -Value $isHyperVRoleInstalled
    $result | Add-Member -MemberType NoteProperty -Name 'IsHyperVPowershellInstalled' -Value $isHyperVPowershellInstalled
    $result | Add-Member -MemberType NoteProperty -Name 'IsCredSSPEnabled' -Value $isCredSSPEnabled
    $result | Add-Member -MemberType NoteProperty -Name 'isRemoteAppEnabled' -Value $isRemoteAppEnabled
    
    $result
    
}


function Get-SSHProbe {
    [CmdletBinding(DefaultParameterSetName='Domain')]
    Param (
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
        [string]$OutputTracker
    )

    #region >> Prep

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

    if ($LocalPasswordSS) {
        $LocalPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($LocalPasswordSS))
    }
    If ($DomainPasswordSS) {
        $DomainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($DomainPasswordSS))
    }

    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
        try {
            if ($(Get-Module -ListAvailable).Name -notcontains 'WinSSH') {$null = Install-Module WinSSH -ErrorAction Stop}
            if ($(Get-Module).Name -notcontains 'WinSSH') {$null = Import-Module WinSSH -ErrorAction Stop}
            Import-Module "$($(Get-Module WinSSH).ModuleBase)\Await\Await.psd1" -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    if ($PSVersionTable.Platform -eq "Unix") {
        # Determine if we have the required Linux commands
        [System.Collections.ArrayList]$LinuxCommands = @(
            "echo"
            "expect"
        )
        [System.Collections.ArrayList]$CommandsNotPresent = @()
        foreach ($CommandName in $LinuxCommands) {
            $CommandCheckResult = command -v $CommandName
            if (!$CommandCheckResult) {
                $null = $CommandsNotPresent.Add($CommandName)
            }
        }

        if ($CommandsNotPresent.Count -gt 0) {
            [System.Collections.ArrayList]$FailedInstalls = @()
            if ($CommandsNotPresent -contains "echo") {
                try {
                    $null = InstallLinuxPackage -PossiblePackageNames "coreutils" -CommandName "echo"
                }
                catch {
                    $null = $FailedInstalls.Add("coreutils")
                }
            }
            if ($CommandsNotPresent -contains "expect") {
                try {
                    $null = InstallLinuxPackage -PossiblePackageNames "expect" -CommandName "expect"
                }
                catch {
                    $null = $FailedInstalls.Add("expect")
                }
            }
    
            if ($FailedInstalls.Count -gt 0) {
                Write-Error "The following Linux packages are required, but were not able to be installed:`n$($FailedInstalls -join "`n")`nHalting!"
                $global:FunctionResult = "1"
                return
            }
        }

        [System.Collections.ArrayList]$CommandsNotPresent = @()
        foreach ($CommandName in $LinuxCommands) {
            $CommandCheckResult = command -v $CommandName
            if (!$CommandCheckResult) {
                $null = $CommandsNotPresent.Add($CommandName)
            }
        }
    
        if ($CommandsNotPresent.Count -gt 0) {
            Write-Error "The following Linux commands are required, but not present on $env:ComputerName:`n$($CommandsNotPresent -join "`n")`nHalting!"
            $global:FunctionResult = "1"
            return
        }
    }

    $TrySSHExe = $False

    #endregion >> Prep
    
    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
        if ($RemoteOSGuess -eq "Windows") {
            if ($LocalUserName) {
                $FullUserName = $LocalUserName
            }
            if ($DomainUserName) {
                $FullUserName = $DomainUserName
            }

            if ($RemoteHostNetworkInfo.FQDN -match "unknown") {
                $HostNameValue = @(
                    $RemoteHostNetworkInfo.IPAddressList | Where-Object {$_ -notmatch "^169"}
                )[0]
            }
            else {
                $HostNameValue = $RemoteHostNetworkInfo.FQDN
            }

            # Install pwsh if it isn't already
            if (!$(Get-Command pwsh -ErrorAction SilentlyContinue)) {
                try {
                    if ($(Get-Module -ListAvailable).Name -notcontains 'ProgramManagement') {$null = Install-Module ProgramManagement -ErrorAction Stop}
                    if ($(Get-Module).Name -notcontains 'ProgramManagement') {$null = Import-Module ProgramManagement -ErrorAction Stop}
                    $InstallPwshResult = Install-Program -ProgramName powershell-core -CommandName pwsh.exe
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }

            # This is basically what we're going for with the below string manipulation:
            #   & pwsh -c {Invoke-Command -HostName zerowin16sshb -KeyFilePath "$HOME\.ssh\zeroadmin_090618-cert.pub" -ScriptBlock {[pscustomobject]@{Output = "ConnectionSuccessful"}} | ConvertTo-Json}
            $PwshRemoteScriptBlockStringArray = @(
                '[pscustomobject]@{'
                '    Output = "ConnectionSuccessful"'
                '    Platform = $PSVersionTable.Platform'
                '    DistroInfo = $PSVersionTable.OS'
                '    Hostnamectl = hostnamectl'
                '}'
            ) | foreach {"    $_"}
            $PwshRemoteScriptBlockString = $PwshRemoteScriptBlockStringArray -join "`n"
            [System.Collections.ArrayList]$PwshInvCmdStringArray = @(
                'Invoke-Command'
                '-HostName'
                $HostNameValue
                '-UserName'
                $FullUserName
            )
            if ($KeyFilePath) {
                $null = $PwshInvCmdStringArray.Add('-KeyFilePath')
                $null = $PwshInvCmdStringArray.Add("'$KeyFilePath'")
            }
            $null = $PwshInvCmdStringArray.Add('-HideComputerName')
            $null = $PwshInvCmdStringArray.Add("-ScriptBlock {`n$PwshRemoteScriptBlockString`n}")
            $null = $PwshInvCmdStringArray.Add('|')
            $null = $PwshInvCmdStringArray.Add('ConvertTo-Json')
            $PwshInvCmdString = $PwshInvCmdStringArray -join " "
            $PwshCmdStringArray = @(
                '&'
                '"' + $(Get-Command pwsh).Source + '"'
                "-c {$PwshInvCmdString}"
            )
            $PwshCmdString = $script:PwshCmdString = $PwshCmdStringArray -join " "

            #region >> Await Attempt Number 1 of 2
            
            $null = Start-AwaitSession
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
            $PSAwaitProcess = $($(Get-Process | Where-Object {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand "`$env:Path = '$env:Path'"
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand -Command $([scriptblock]::Create($PwshCmdString))
            Start-Sleep -Seconds 5

            # This will either not prompt at all, prompt to accept the RemoteHost's RSA Host Key, or prompt for a password
            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

            [System.Collections.ArrayList]$CheckForExpectedResponses = @()
            $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
            $Counter = 0
            while (![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) -and
            ![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("'s password:")) -and 
            ![bool]$($($CheckForExpectedResponses -split "`n") -match "^}") -and $Counter -le 30
            ) {
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                if ($CheckResponsesOutput -match "must be greater than zero" -or $CheckResponsesOutput[-1] -notmatch "[a-zA-Z]") {
                    break
                }
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 31) {
                Write-Warning "SSH via 'pwsh -c {Invoke-Command ...}' timed out!"
                
                if ($PSAwaitProcess.Id) {
                    try {
                        $null = Stop-AwaitSession
                    }
                    catch {
                        if ($PSAwaitProcess.Id -eq $PID) {
                            Write-Error "The PSAwaitSession never spawned! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                            }
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                            }
                        }
                    }
                }
            }
            #endregion >> Await Attempt 1 of 2

            $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}
            # Make sure we didn't already throw an error related to the Remote Host not having PowerShell Remoting configured
            if ($CheckResponsesOutput -match "background process reported an error") {
                $TrySSHExe = $True
            }

            #region >> Await Attempt 2 of 2
            
            # If $CheckResponsesOutput contains the string "must be greater than zero", then something broke with the Await Module.
            # Most of the time, just trying again resolves any issues
            if ($CheckResponsesOutput -match "must be greater than zero" -or $CheckResponsesOutput[-1] -notmatch "[a-zA-Z]" -and
            ![bool]$($CheckResponsesOutput -match "background process reported an error")) {
                if ($PSAwaitProcess.Id) {
                    try {
                        $null = Stop-AwaitSession
                    }
                    catch {
                        if ($PSAwaitProcess.Id -eq $PID) {
                            Write-Error "The PSAwaitSession never spawned! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                            }
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                            }
                        }
                    }
                }

                $null = Start-AwaitSession
                Start-Sleep -Seconds 1
                $null = Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
                $PSAwaitProcess = $($(Get-Process | Where-Object {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
                Start-Sleep -Seconds 1
                $null = Send-AwaitCommand "`$env:Path = '$env:Path'"
                Start-Sleep -Seconds 1
                $null = Send-AwaitCommand -Command $([scriptblock]::Create($PwshCmdString))
                Start-Sleep -Seconds 5

                # This will either not prompt at all, prompt to accept the RemoteHost's RSA Host Key, or prompt for a password
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                [System.Collections.ArrayList]$CheckForExpectedResponses = @()
                $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                $Counter = 0
                while ($SuccessOrAcceptHostKeyOrPwdPrompt -notmatch [regex]::Escape("Are you sure you want to continue connecting (yes/no)?") -and
                $SuccessOrAcceptHostKeyOrPwdPrompt -notmatch [regex]::Escape("'s password:") -and 
                $SuccessOrAcceptHostKeyOrPwdPrompt -notmatch "^}" -and $Counter -le 30
                ) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 31) {
                    Write-Warning "SSH via 'pwsh -c {Invoke-Command ...}' timed out!"
                    
                    if ($PSAwaitProcess.Id) {
                        try {
                            $null = Stop-AwaitSession
                        }
                        catch {
                            if ($PSAwaitProcess.Id -eq $PID) {
                                Write-Error "The PSAwaitSession never spawned! Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            else {
                                if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                }
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                }
                            }
                        }
                    }
                }
            }

            #endregion >> Await Attempt 2 of 2

            $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}
            # Make sure we didn't already throw an error related to the Remote Host not having PowerShell Remoting configured
            if ($CheckResponsesOutput -match "background process reported an error") {
                $TrySSHExe = $True
            }

            # At this point, if we don't have the expected output, we need to fail
            if ($CheckResponsesOutput -match "must be greater than zero" -or $CheckResponsesOutput[-1] -notmatch "[a-zA-Z]" -and
            ![bool]$($CheckResponsesOutput -match "background process reported an error")) {
                Write-Error "Something went wrong with the PowerShell Await Module! Halting!"
                $global:FunctionResult = "1"

                if ($PSAwaitProcess.Id) {
                    try {
                        $null = Stop-AwaitSession
                    }
                    catch {
                        if ($PSAwaitProcess.Id -eq $PID) {
                            Write-Error "The PSAwaitSession never spawned! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                            }
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                            }
                        }
                    }
                }

                return
            }

            # Now we should either have a prompt to accept the host key, a prompt for a password, or it already worked...

            if ($CheckResponsesOutput -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) {
                $null = Send-AwaitCommand "yes"
                Start-Sleep -Seconds 3
                
                # This will either not prompt at all or prompt for a password
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                [System.Collections.ArrayList]$CheckExpectedSendYesOutput = @()
                $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                $Counter = 0
                while (![bool]$($($CheckExpectedSendYesOutput -split "`n") -match [regex]::Escape("'s password:")) -and 
                ![bool]$($($CheckExpectedSendYesOutput -split "`n") -match "^}") -and $Counter -le 30
                ) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 31) {
                    Write-Error "Sending 'yes' to accept the ssh host key timed out!"
                    $global:FunctionResult = "1"
                    
                    if ($PSAwaitProcess.Id) {
                        try {
                            $null = Stop-AwaitSession
                        }
                        catch {
                            if ($PSAwaitProcess.Id -eq $PID) {
                                Write-Error "The PSAwaitSession never spawned! Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            else {
                                if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                }
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                }
                            }
                        }
                    }

                    return
                }

                $CheckSendYesOutput = $CheckExpectedSendYesOutput | foreach {$_ -split "`n"}
                
                if ($CheckSendYesOutput -match [regex]::Escape("'s password:")) {
                    if ($LocalPassword) {
                        $null = Send-AwaitCommand $LocalPassword
                    }
                    if ($DomainPassword) {
                        $null = Send-AwaitCommand $DomainPassword
                    }
                    Start-Sleep -Seconds 3

                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                    [System.Collections.ArrayList]$JsonOutputPrep = @()
                    $null = $JsonOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    $Counter = 0
                    while (![bool]$($($JsonOutputPrep -split "`n") -match "^}") -and $Counter -le 30) {
                        $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                        if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                            $null = $JsonOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                        }
                        Start-Sleep -Seconds 1
                        $Counter++
                    }
                    if ($Counter -eq 31) {
                        Write-Verbose "Sending the user's password timed out!"

                        if ($PSAwaitProcess.Id) {
                            try {
                                $null = Stop-AwaitSession
                            }
                            catch {
                                if ($PSAwaitProcess.Id -eq $PID) {
                                    Write-Error "The PSAwaitSession never spawned! Halting!"
                                    $global:FunctionResult = "1"
                                    return
                                }
                                else {
                                    if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                        Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                    }
                                    while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                        Write-Warning "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                        Start-Sleep -Seconds 1
                                    }
                                }
                            }
                        }

                        $TrySSHExe = $True
                    }

                    [System.Collections.ArrayList]$JsonOutputPrep = $($JsonOutputPrep | foreach {$_ -split "`n"}) | Where-Object {$_ -notmatch "^PS "}
                    if (![bool]$($JsonOutputPrep[0] -match "^{")) {
                        $null = $JsonOutputPrep.Insert(0,'{')
                    }
                }
            }
            elseif ($CheckResponsesOutput -match [regex]::Escape("'s password:")) {
                if ($LocalPassword) {
                    $null = Send-AwaitCommand $LocalPassword
                }
                if ($DomainPassword) {
                    $null = Send-AwaitCommand $DomainPassword
                }
                Start-Sleep -Seconds 3

                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                [System.Collections.ArrayList]$JsonOutputPrep = @()
                $null = $JsonOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                $Counter = 0
                while (![bool]$($($JsonOutputPrep -split "`n") -match "^}") -and $Counter -le 30) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                        $null = $JsonOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    }
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 31) {
                    Write-Verbose "Sending the user's password timed out!"

                    if ($PSAwaitProcess.Id) {
                        try {
                            $null = Stop-AwaitSession
                        }
                        catch {
                            if ($PSAwaitProcess.Id -eq $PID) {
                                Write-Error "The PSAwaitSession never spawned! Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            else {
                                if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                }
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Write-Warning "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                }
                            }
                        }
                    }

                    $TrySSHExe = $True
                }

                [System.Collections.ArrayList]$JsonOutputPrep = $($JsonOutputPrep | foreach {$_ -split "`n"}) | Where-Object {$_ -notmatch "^PS "}
                if (![bool]$($JsonOutputPrep[0] -match "^{")) {
                    $null = $JsonOutputPrep.Insert(0,'{')
                }
            }
            else {
                [System.Collections.ArrayList]$JsonOutputPrep = $($CheckResponsesOutput | foreach {$_ -split "`n"}) | Where-Object {
                    $_ -notmatch "^PS " -and ![System.String]::IsNullOrWhiteSpace($_)
                }
                $EndOfInputLineContent = $JsonOutputPrep -match [regex]::Escape("ConvertTo-Json}")
                $JsonOutputIndex = $JsonOutputPrep.IndexOf($EndOfInputLineContent) + 1

                [System.Collections.ArrayList]$JsonOutputPrep = $JsonOutputPrep[$JsonOutputIndex..$($JsonOutputPrep.Count-1)]

                if (![bool]$($JsonOutputPrep[0] -match "^{")) {
                    $null = $JsonOutputPrep.Insert(0,'{')
                }
            }

            if (!$TrySSHExe) {
                $IndexesOfOpenBracket = for ($i=0; $i -lt $JsonOutputPrep.Count; $i++) {
                    if ($JsonOutputPrep[$i] -match "^{") {
                        $i
                    }
                }
                $LastIndexOfOpenBracket = $($IndexesOfOpenBracket | Measure-Object -Maximum).Maximum
                $IndexesOfCloseBracket = for ($i=0; $i -lt $JsonOutputPrep.Count; $i++) {
                    if ($JsonOutputPrep[$i] -match "^}") {
                        $i
                    }
                }
                $LastIndexOfCloseBracket = $($IndexesOfCloseBracket | Measure-Object -Maximum).Maximum
                [System.Collections.ArrayList]$JsonOutputPrep = $JsonOutputPrep[$LastIndexOfOpenBracket..$LastIndexOfCloseBracket] | foreach {$_ -split "`n"}
                if (![bool]$($JsonOutputPrep[0] -match "^{")) {
                    $null = $JsonOutputPrep.Insert(0,'{')
                }

                $FinalJson = $JsonOutputPrep | foreach {if (![System.String]::IsNullOrWhiteSpace($_)) {$_.Trim()}}

                try {
                    $SSHCheckAsJson = $FinalJson | ConvertFrom-Json
                }
                catch {
                    $TrySSHExe = $True
                }
            }

            if ($PSAwaitProcess.Id) {
                try {
                    $null = Stop-AwaitSession
                }
                catch {
                    if ($PSAwaitProcess.Id -eq $PID) {
                        Write-Error "The PSAwaitSession never spawned! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                    else {
                        if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                            Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                        }
                        while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                            Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                            Start-Sleep -Seconds 1
                        }
                    }
                }
            }

            if ($SSHCheckAsJson.Output -ne "ConnectionSuccessful") {
                $TrySSHExe = $True
            }

            # TODO: Remove this after testing finished
            #$SSHCheckAsJson
            
            # NOTE: The below $ShellDetermination refers to the shell you will (probably) end up in if you use an ssh command, NOT PSRemoting
            if ($SSHCheckAsJson.Output -eq "ConnectionSuccessful") {
                if ($SSHCheckAsJson.Platform -eq "Win32NT") {
                    $OSDetermination = "Windows"
                    $ShellDetermination = "pwsh"
                    [System.Collections.ArrayList]$OSVersionInfo = @()
                    if ($SSHCheckAsJson.DistroInfo) {
                        $null = $OSVersionInfo.Add($SSHCheckAsJson.DistroInfo)
                    }
                    if ($SSHCheckAsJson.Hostnamectl) {
                        $null = $OSVersionInfo.Add($SSHCheckAsJson.Hostnamectl)
                    }
                }
                else {
                    $OSDetermination = "Linux"
                    $ShellDetermination = "pwsh"
                    [System.Collections.ArrayList]$OSVersionInfo = @()
                    if ($SSHCheckAsJson.DistroInfo) {
                        $null = $OSVersionInfo.Add($SSHCheckAsJson.DistroInfo)
                    }
                    if ($SSHCheckAsJson.Hostnamectl) {
                        $null = $OSVersionInfo.Add($SSHCheckAsJson.Hostnamectl)
                    }
                }

                $FinalOutput = [pscustomobject]@{
                    OS              = $OSDetermination
                    Shell           = $ShellDetermination
                    OSVersionInfo   = $OSVersionInfo
                }
            }
        }

        if ($RemoteOSGuess -eq "Linux" -or $TrySSHExe) {
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
            #     ssh -t pdadmin@192.168.2.10 "echo 'ConnectionSuccessful'"
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
            $Bytes = [System.Text.Encoding]::Unicode.GetBytes('$PSVersionTable | ConvertTo-Json')
            $EncodedCommandPSVerTable = [Convert]::ToBase64String($Bytes)
            $Bytes = [System.Text.Encoding]::Unicode.GetBytes('"Cim OS Info: " + $(Get-CimInstance Win32_OperatingSystem).Caption')
            $EncodedCommandWinOSCim = [Convert]::ToBase64String($Bytes)
            $SSHScript = @(
                "echo ConnectionSuccessful"
                "echo 111RootDirInfo111"
                "cd /"
                "dir"
                "echo 111ProcessInfo111"
                'Get-Process -Id `$PID'
                "echo 111PwshJson111"
                "pwsh -NoProfile -EncodedCommand $EncodedCommandPSVerTable"
                "echo 111PowerShellCimInfo111"
                "powershell -NoProfile -EncodedCommand $EncodedCommandWinOSCim"
                "echo 111UnameOutput111"
                "uname -a"
                "echo 111HostnamectlOutput111"
                "hostnamectl"
            )
            $SSHScript = $SSHScript -join "; "
            $null = $SSHCmdStringArray.Add($('"' + $SSHScript + '"'))
            # NOTE: The below -replace regex string removes garbage escape sequences like: [116;1H
            $SSHCmdString = $script:SSHCmdString = '@($(' + $($SSHCmdStringArray -join " ") + ') -replace "\e\[(\d+;)*(\d+)?[ABCDHJKfmsu]","") 2>$null'

            #region >> Await Attempt Number 1 of 2
            
            $null = Start-AwaitSession
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
            $PSAwaitProcess = $($(Get-Process | Where-Object {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand "`$env:Path = '$env:Path'"
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand -Command $([scriptblock]::Create($SSHCmdString))
            Start-Sleep -Seconds 5

            # This will either not prompt at all, prompt to accept the RemoteHost's RSA Host Key, or prompt for a password
            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

            [System.Collections.ArrayList]$CheckForExpectedResponses = @()
            $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
            $Counter = 0
            while (![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) -and
            ![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("'s password:")) -and 
            ![bool]$($($CheckForExpectedResponses -split "`n") -match "^}") -and $Counter -le 30
            ) {
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                if ($CheckResponsesOutput -match "must be greater than zero" -or $CheckResponsesOutput[-1] -notmatch "[a-zA-Z]") {
                    break
                }
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 31) {
                Write-Warning "SSH via 'ssh -t ...' timed out!"
                
                if ($PSAwaitProcess.Id) {
                    try {
                        $null = Stop-AwaitSession
                    }
                    catch {
                        if ($PSAwaitProcess.Id -eq $PID) {
                            Write-Error "The PSAwaitSession never spawned! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                            }
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                            }
                        }
                    }
                }
            }
            #endregion >> Await Attempt 1 of 2

            $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}
            
            #region >> Await Attempt 2 of 2
            
            # If $CheckResponsesOutput contains the string "must be greater than zero", then something broke with the Await Module.
            # Most of the time, just trying again resolves any issues
            if ($CheckResponsesOutput -match "must be greater than zero" -or $CheckResponsesOutput[-1] -notmatch "[a-zA-Z]" -and
            ![bool]$($CheckResponsesOutput -match "background process reported an error")) {
                if ($PSAwaitProcess.Id) {
                    try {
                        $null = Stop-AwaitSession
                    }
                    catch {
                        if ($PSAwaitProcess.Id -eq $PID) {
                            Write-Error "The PSAwaitSession never spawned! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                            }
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                            }
                        }
                    }
                }

                $null = Start-AwaitSession
                Start-Sleep -Seconds 1
                $null = Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
                $PSAwaitProcess = $($(Get-Process | Where-Object {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
                Start-Sleep -Seconds 1
                $null = Send-AwaitCommand "`$env:Path = '$env:Path'"
                Start-Sleep -Seconds 1
                $null = Send-AwaitCommand -Command $([scriptblock]::Create($SSHCmdString))
                Start-Sleep -Seconds 5

                # This will either not prompt at all, prompt to accept the RemoteHost's RSA Host Key, or prompt for a password
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                [System.Collections.ArrayList]$CheckForExpectedResponses = @()
                $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                $Counter = 0
                while ($SuccessOrAcceptHostKeyOrPwdPrompt -notmatch [regex]::Escape("Are you sure you want to continue connecting (yes/no)?") -and
                $SuccessOrAcceptHostKeyOrPwdPrompt -notmatch [regex]::Escape("'s password:") -and 
                $SuccessOrAcceptHostKeyOrPwdPrompt -notmatch "^}" -and $Counter -le 30
                ) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 31) {
                    Write-Warning "SSH via 'ssh -t ...' timed out!"
                    
                    if ($PSAwaitProcess.Id) {
                        try {
                            $null = Stop-AwaitSession
                        }
                        catch {
                            if ($PSAwaitProcess.Id -eq $PID) {
                                Write-Error "The PSAwaitSession never spawned! Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            else {
                                if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                }
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                }
                            }
                        }
                    }
                }
            }

            #endregion >> Await Attempt 2 of 2

            $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}

            # At this point, if we don't have the expected output, we need to fail
            if ($CheckResponsesOutput -match "must be greater than zero" -or $CheckResponsesOutput[-1] -notmatch "[a-zA-Z]" -and
            ![bool]$($CheckResponsesOutput -match "background process reported an error")) {
                Write-Error "Something went wrong with the PowerShell Await Module! Halting!"
                $global:FunctionResult = "1"

                if ($PSAwaitProcess.Id) {
                    try {
                        $null = Stop-AwaitSession
                    }
                    catch {
                        if ($PSAwaitProcess.Id -eq $PID) {
                            Write-Error "The PSAwaitSession never spawned! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                            }
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                            }
                        }
                    }
                }

                return
            }

            # Now we should either have a prompt to accept the host key, a prompt for a password, or it already worked...

            if ($CheckResponsesOutput -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) {
                $null = Send-AwaitCommand "yes"
                Start-Sleep -Seconds 3
                
                # This will either not prompt at all or prompt for a password
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                [System.Collections.ArrayList]$CheckExpectedSendYesOutput = @()
                $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                $Counter = 0
                while (![bool]$($($CheckExpectedSendYesOutput -split "`n") -match [regex]::Escape("'s password:")) -and 
                ![bool]$($($CheckExpectedSendYesOutput -split "`n") -match "^}") -and $Counter -le 30
                ) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 31) {
                    Write-Error "Sending 'yes' to accept the ssh host key timed out!"
                    $global:FunctionResult = "1"
                    
                    if ($PSAwaitProcess.Id) {
                        try {
                            $null = Stop-AwaitSession
                        }
                        catch {
                            if ($PSAwaitProcess.Id -eq $PID) {
                                Write-Error "The PSAwaitSession never spawned! Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            else {
                                if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                }
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                }
                            }
                        }
                    }

                    return
                }

                $CheckSendYesOutput = $CheckExpectedSendYesOutput | foreach {$_ -split "`n"}
                
                if ($CheckSendYesOutput -match [regex]::Escape("'s password:")) {
                    if ($LocalPassword) {
                        $null = Send-AwaitCommand $LocalPassword
                    }
                    if ($DomainPassword) {
                        $null = Send-AwaitCommand $DomainPassword
                    }
                    Start-Sleep -Seconds 3

                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                    [System.Collections.ArrayList]$SSHOutputPrep = @()
                    $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    $Counter = 0
                    while (![bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful") -and $Counter -le 30) {
                        $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                        if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                            $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                        }
                        Start-Sleep -Seconds 1
                        $Counter++
                    }
                    if ($Counter -eq 31) {
                        Write-Error "Sending the user's password timed out!"
                        $global:FunctionResult = "1"

                        if ($PSAwaitProcess.Id) {
                            try {
                                $null = Stop-AwaitSession
                            }
                            catch {
                                if ($PSAwaitProcess.Id -eq $PID) {
                                    Write-Error "The PSAwaitSession never spawned! Halting!"
                                    $global:FunctionResult = "1"
                                    return
                                }
                                else {
                                    if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                        Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                    }
                                    while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                        Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                        Start-Sleep -Seconds 1
                                    }
                                }
                            }
                        }

                        return
                    }
                }
            }
            elseif ($CheckResponsesOutput -match [regex]::Escape("'s password:")) {
                if ($LocalPassword) {
                    $null = Send-AwaitCommand $LocalPassword
                }
                if ($DomainPassword) {
                    $null = Send-AwaitCommand $DomainPassword
                }
                Start-Sleep -Seconds 3

                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                [System.Collections.ArrayList]$SSHOutputPrep = @()
                $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                $Counter = 0
                while (![bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful") -and $Counter -le 30) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                        $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    }
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 31) {
                    Write-Error "Sending the user's password timed out!"
                    $global:FunctionResult = "1"

                    if ($PSAwaitProcess.Id) {
                        try {
                            $null = Stop-AwaitSession
                        }
                        catch {
                            if ($PSAwaitProcess.Id -eq $PID) {
                                Write-Error "The PSAwaitSession never spawned! Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            else {
                                if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                }
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                }
                            }
                        }
                    }

                    return
                }
            }

            if ($PSAwaitProcess.Id) {
                try {
                    $null = Stop-AwaitSession
                }
                catch {
                    if ($PSAwaitProcess.Id -eq $PID) {
                        Write-Error "The PSAwaitSession never spawned! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                    else {
                        if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                            Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                        }
                        while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                            Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                            Start-Sleep -Seconds 1
                        }
                    }
                }
            }

            # TODO: Remove this after testing finished
            #$SSHOutputPrep

            if ([bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful")) {
                if ($SSHOutputPrep -match "ConnectionSuccessful; echo 111RootDirInfo111;") {
                    $OSDetermination = "Windows"
                    $ShellDetermination = "cmd"
                    $OSVersionInfo = $null
                }
                elseif ($SSHOutputPrep -match "111RootDirInfo111" -and $SSHOutputPrep -match "Directory:.*[a-zA-Z]:\\") {
                    $OSDetermination = "Windows"
                    if ($SSHOutputPrep -match "111ProcessInfo111" -and $SSHOutputPrep -match "Name[\s]+:[\s]+powershell") {
                        $ShellDetermination = "powershell"
                        # The below $OSVersionInfo will be a string that looks something like:
                        #   Microsoft Windows Server 2016 Standard Evaluation
                        $OSVersionInfo = $($($($SSHOutputPrep -split "`n") -match "Cim OS Info:") -replace "Cim OS Info: ","").Trim()
                    }
                    elseif ($SSHOutputPrep -match "111ProcessInfo111" -and $SSHOutputPrep -match "Name[\s]+:[\s]+pwsh") {
                        $ShellDetermination = "pwsh"
                        # The below $OSVersionInfo will be a string that looks something like:
                        #   Microsoft Windows Server 2016 Standard Evaluation
                        $OSVersionInfo = $($($($SSHOutputPrep -split "`n") -match "Cim OS Info:") -replace "Cim OS Info: ","").Trim()
                    }
                }
                elseif ($SSHOutputPrep -match "111RootDirInfo111" -and $SSHOutputPrep -match " etc " -and 
                !$($SSHOutputPrep -match "111RootDirInfo111" -and $SSHOutputPrep -match "Directory:.*[a-zA-Z]:\\")
                ) {
                    $OSDetermination = "Linux"
                    if ($SSHOutputPrep -match "111ProcessInfo111" -and $SSHOutputPrep -match "Name[\s]+:[\s]+pwsh") {
                        $ShellDetermination = "pwsh"
                    }
                    else {
                        $ShellDetermination = "bash"
                    }

                    #$SSHOutputPrep | Export-Clixml "$HOME\SSHOutputPrep.xml"

                    $UnameOutputHeader = $($SSHOutputPrep -split "`n") -match "111UnameOutput111"
                    $UnameOutputHeaderIndex = $($SSHOutputPrep -split "`n").IndexOf($UnameOutputHeader)
                    if ($UnameOutputHeaderIndex -eq "-1") {
                        $UnameOutputHeaderIndex = $($SSHOutputPrep -split "`n").IndexOf($UnameOutputHeader[0])
                    }
                    $UnameOutput = $($SSHOutputPrep -split "`n")[$($UnameOutputHeaderIndex + 1)]
                    $HostnamectlOutput = $($SSHOutputPrep -split "`n")[$($UnameOutputHeaderIndex + 2)..$($($SSHOutputPrep -split "`n").Count-1)]
                    [System.Collections.ArrayList]$OSVersionInfo = @()
                    if ($UnameOutput) {
                        $null = $OSVersionInfo.Add($UnameOutput)
                    }
                    if ($HostnamectlOutput) {
                        $null = $OSVersionInfo.Add($HostnamectlOutput)
                    }
                }

                $FinalOutput = [pscustomobject]@{
                    OS              = $OSDetermination
                    Shell           = $ShellDetermination
                    OSVersionInfo   = $OSVersionInfo
                }
            }
        }

        if ($SSHCheckAsJson.Output -ne "ConnectionSuccessful" -and ![bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful")) {
            Write-Error "SSH attempts via PowerShell Core 'Invoke-Command' and ssh.exe have failed!"
            $global:FunctionResult = "1"
            return
        }
    }
    elseif ($PSVersionTable.Platform -eq "Unix") {
        if ($RemoteOSGuess -eq "Windows") {
            if ($LocalUserName) {
                $FullUserName = $LocalUserName
            }
            if ($DomainUserName) {
                $FullUserName = $DomainUserName
            }

            if ($RemoteHostNetworkInfo.FQDN -match "unknown") {
                $HostNameValue = @(
                    $RemoteHostNetworkInfo.IPAddressList | Where-Object {$_ -notmatch "^169"}
                )[0]
            }
            else {
                $HostNameValue = $RemoteHostNetworkInfo.FQDN
            }

            # This is basically what we're going for with the below string manipulation:
            #   & pwsh -c {Invoke-Command -HostName zerowin16sshb -KeyFilePath "$HOME\.ssh\zeroadmin_090618-cert.pub" -ScriptBlock {[pscustomobject]@{Output = "ConnectionSuccessful"}} | ConvertTo-Json}
            $PwshRemoteScriptBlockStringArray = @(
                '[pscustomobject]@{'
                '    Output = \"ConnectionSuccessful\"'
                '    Platform = (Get-Variable PSVersionTable -ValueOnly).Platform'
                '    DistroInfo = (Get-Variable PSVersionTable -ValueOnly).OS'
                '    Hostnamectl = hostnamectl'
                '}'
            ) | foreach {"    $_"}
            $PwshRemoteScriptBlockString = $PwshRemoteScriptBlockStringArray -join "`n"
            [System.Collections.ArrayList]$PwshInvCmdStringArray = @(
                'Invoke-Command'
                '-HostName'
                $HostNameValue
                '-UserName'
                $FullUserName
            )
            if ($KeyFilePath) {
                $null = $PwshInvCmdStringArray.Add('-KeyFilePath')
                $null = $PwshInvCmdStringArray.Add("'$KeyFilePath'")
            }
            $null = $PwshInvCmdStringArray.Add('-HideComputerName')
            $null = $PwshInvCmdStringArray.Add("-ScriptBlock {`n$PwshRemoteScriptBlockString`n}")
            $null = $PwshInvCmdStringArray.Add('|')
            $null = $PwshInvCmdStringArray.Add('ConvertTo-Json')
            $PwshInvCmdString = $PwshInvCmdStringArray -join " "
            $PwshCmdStringArray = @(
                $(Get-Command pwsh).Source
                "-c {$PwshInvCmdString}"
            )
            $PwshCmdString = $script:PwshCmdString = $PwshCmdStringArray -join " "

            $FinalPassword = if ($DomainPassword) {$DomainPassword} else {$LocalPassword}

            # NOTE: 'timeout' is in seconds
            $ExpectScriptPrep = @(
                'expect - << EOF'
                'set timeout 10'
                "spawn $PwshCmdString"
                'match_max 100000'
                'expect {'
                '    \"*(yes/no)?*\" {'
                '        send -- \"yes\r\"'
                '        exp_continue'
                '    }'
                '    \"*password:*\" {'
                "        send -- \`"$FinalPassword\r\`""
                '        expect \"*\"'
                '        expect eof'
                '    }'
                '}'
                'EOF'
            )
            $ExpectScript = $ExpectScriptPrep -join "`n"

            # The below $ExpectOutput is an array of strings
            $ExpectOutput = bash -c "$ExpectScript"

            $SSHOutputPrep = $ExpectOutput -replace "\e\[(\d+;)*(\d+)?[ABCDHJKfmsu]",""

            # Sample Contents of $ExpectOutput
            <#
            spawn pwsh -c Invoke-Command -HostName centos7nodomain -UserName vagrant -ScriptBlock {[pscustomobject]@{Output = "ConnectionSuccessful"}} | ConvertTo-Json
            vagrant@centos7nodomain's password:
            {
            "Output": "ConnectionSuccessful",
            "Platform": "Unix",
            "DistroInfo": "Linux 3.10.0-862.2.3.el7.x86_64 #1 SMP Wed May 9 18:05:47 UTC 2018",
            "PSComputerName": "centos7nodomain",
            "RunspaceId": "ce31711a-87eb-47b8-809d-6598990d54c4",
            "PSShowComputerName": true
            }
            #>

            $JsonStartIndex = $SSHOutputPrep.IndexOf($($SSHOutputPrep -match '"Output"'))
            $JsonEndIndex = $SSHOutputPrep.IndexOf($($SSHOutputPrep -match '^}$'))
            [System.Collections.ArrayList]$FinalJson = $SSHOutputPrep[$JsonStartIndex..$JsonEndIndex]
            $FinalJson.Insert(0,"{")

            try {
                $SSHCheckAsJson = $FinalJson | ConvertFrom-Json
            }
            catch {
                $TrySSHExe = $True
            }

            if ($SSHCheckAsJson.Output -ne "ConnectionSuccessful") {
                $TrySSHExe = $True
            }

            if ($SSHCheckAsJson.Output -eq "ConnectionSuccessful") {
                if ($SSHCheckAsJson.Platform -eq "Win32NT") {
                    $OSDetermination = "Windows"
                    $ShellDetermination = "pwsh"
                    [System.Collections.ArrayList]$OSVersionInfo = @()
                    if ($SSHCheckAsJson.DistroInfo) {
                        $null = $OSVersionInfo.Add($SSHCheckAsJson.DistroInfo)
                    }
                    if ($SSHCheckAsJson.Hostnamectl) {
                        $null = $OSVersionInfo.Add($SSHCheckAsJson.Hostnamectl)
                    }
                }
                else {
                    $OSDetermination = "Linux"
                    $ShellDetermination = "pwsh"
                    [System.Collections.ArrayList]$OSVersionInfo = @()
                    if ($SSHCheckAsJson.DistroInfo) {
                        $null = $OSVersionInfo.Add($SSHCheckAsJson.DistroInfo)
                    }
                    if ($SSHCheckAsJson.Hostnamectl) {
                        $null = $OSVersionInfo.Add($SSHCheckAsJson.Hostnamectl)
                    }
                }

                $FinalOutput = [pscustomobject]@{
                    OS              = $OSDetermination
                    Shell           = $ShellDetermination
                    OSVersionInfo   = $OSVersionInfo
                }
            }
        }

        if ($RemoteOSGuess -eq "Linux" -or $TrySSHExe) {
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
            #     ssh -t pdadmin@192.168.2.10 "echo 'ConnectionSuccessful'"
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
            $Bytes = [System.Text.Encoding]::Unicode.GetBytes('$PSVersionTable | ConvertTo-Json')
            $EncodedCommandPSVerTable = [Convert]::ToBase64String($Bytes)
            $Bytes = [System.Text.Encoding]::Unicode.GetBytes('"Cim OS Info: " + $(Get-CimInstance Win32_OperatingSystem).Caption')
            $EncodedCommandWinOSCim = [Convert]::ToBase64String($Bytes)
            $SSHScript = @(
                "echo ConnectionSuccessful"
                "echo 111RootDirInfo111"
                "cd /"
                "dir"
                "echo 111ProcessInfo111"
                'Get-Process -Id \\\$PID'
                "echo 111PwshJson111"
                "pwsh -NoProfile -EncodedCommand $EncodedCommandPSVerTable"
                "echo 111PowerShellCimInfo111"
                "powershell -NoProfile -EncodedCommand $EncodedCommandWinOSCim"
                "echo 111UnameOutput111"
                "uname -a"
                "echo 111HostnamectlOutput111"
                "hostnamectl"
            )
            #$SSHScript = $SSHScript -join "; "
            #$null = $SSHCmdStringArray.Add($($SSHScript))
            #$null = $SSHCmdStringArray.Add($('"' + $SSHScript + '"'))
            # NOTE: The below -replace regex string removes garbage escape sequences like: [116;1H
            #$SSHCmdString = $script:SSHCmdString = '@($(' + $($SSHCmdStringArray -join " ") + ') -replace "\e\[(\d+;)*(\d+)?[ABCDHJKfmsu]","") 2>$null'
            $SSHCmdString = $script:SSHCmdString = $SSHCmdStringArray -join " "

            $FinalPassword = if ($DomainPassword) {$DomainPassword} else {$LocalPassword}

            $ExpectScriptPrep = @(
                'expect - << EOF'
                'set timeout 10'
                "spawn $SSHCmdString"
                'match_max 100000'
                'expect {'
                '    \"*(yes/no)?*\" {'
                '        send -- \"yes\r\"'
                '        exp_continue'
                '    }'
                '    \"*password:*\" {'
                "        send -- \`"$FinalPassword\r\`""
                '        expect \"*\"'
                '        exp_continue'
                '    }'
                '}'
                'expect \"*\"'
                $SSHScript | foreach {'send -- \"' + $_ + '\r\"' + "`n" + 'expect \"*\"'}
                'expect eof'
                'EOF'
            )
            $ExpectScript = $ExpectScriptPrep -join "`n"
            
            # The below $ExpectOutput is an array of strings
            $ExpectOutput = bash -c "$ExpectScript"

            # NOTE: The below -replace regex string removes garbage escape sequences like: [116;1H
            $SSHOutputPrep = $ExpectOutput -replace "\e\[(\d+;)*(\d+)?[ABCDHJKfmsu]",""

            if ([bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful")) {
                if ([bool]$($($SSHOutputPrep -split "`n") -match "'Get-Process' is not recognized as an internal or external command")) {
                    $OSDetermination = "Windows"
                    $ShellDetermination = "cmd"
                    $OSVersionInfo = $null
                }
                elseif ($SSHOutputPrep -match "111RootDirInfo111" -and $SSHOutputPrep -match "Directory:.*[a-zA-Z]:\\") {
                    $OSDetermination = "Windows"
                    if ($($SSHOutputPrep -join "") -match "111ProcessInfo.*Process.*powershell.*111PwshJson111") {
                        $ShellDetermination = "powershell"
                        # The below $OSVersionInfo will be a string that looks something like:
                        #   Microsoft Windows Server 2016 Standard Evaluation
                        $OSVersionInfo = $($($($SSHOutputPrep -split "`n") -match "Cim OS Info:") -replace "Cim OS Info: ","").Trim()
                    }
                    elseif ($($SSHOutputPrep -join "") -match "111ProcessInfo.*Process.*pwsh.*111PwshJson111") {
                        $ShellDetermination = "pwsh"
                        # The below $OSVersionInfo will be a string that looks something like:
                        #   Microsoft Windows Server 2016 Standard Evaluation
                        $OSVersionInfo = $($($($SSHOutputPrep -split "`n") -match "Cim OS Info:") -replace "Cim OS Info: ","").Trim()
                    }
                }
                elseif ($($SSHOutputPrep -join "") -match "111RootDirInfo111.*etc.*111ProcessInfo111" -and 
                !$($($SSHOutputPrep -join "") -match "111RootDirInfo111.*Windows.*111ProcessInfo111")
                ) {
                    $OSDetermination = "Linux"
                    if ($($SSHOutputPrep -join "") -match "111ProcessInfo.*Process.*pwsh.*111PwshJson111") {
                        $ShellDetermination = "pwsh"
                    }
                    else {
                        $ShellDetermination = "bash"
                    }

                    $UnameOutputHeaderIndex = $($SSHOutputPrep -split "`n").IndexOf($($($SSHOutputPrep -split "`n") -match "uname -a"))
                    $UnameOutput = $($SSHOutputPrep -split "`n")[$($UnameOutputHeaderIndex + 1)]
                    $HostnamectlOutput = $($SSHOutputPrep -split "`n")[$($UnameOutputHeaderIndex + 2)..$($($SSHOutputPrep -split "`n").Count-1)]
                    [System.Collections.ArrayList]$OSVersionInfo = @()
                    if ($UnameOutput) {
                        $null = $OSVersionInfo.Add($UnameOutput)
                    }
                    if ($HostnamectlOutput) {
                        $null = $OSVersionInfo.Add($HostnamectlOutput)
                    }
                }

                $FinalOutput = [pscustomobject]@{
                    OS              = $OSDetermination
                    Shell           = $ShellDetermination
                    OSVersionInfo   = $OSVersionInfo
                }
            }
        }
    }
    else {
        Write-Error "Unable to test SSH! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $FinalOutput
}


<#
    
    .SYNOPSIS
        Enumerates all of the local disks of the system.
    
    .DESCRIPTION
        Enumerates all of the local disks of the system.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers

    .PARAMETER DiskId
        This parameter is OPTIONAL.

        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-StorageDisk
    
#>
function Get-StorageDisk {
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $DiskId
    )
    
    Import-Module CimCmdlets
    Import-Module Microsoft.PowerShell.Utility
    
    <#
    .Synopsis
        Name: Get-Disks
        Description: Gets all the local disks of the machine.
    
    .Parameters
        $DiskId: The unique identifier of the disk desired (Optional - for cases where only one disk is desired).
    
    .Returns
        The local disk(s).
    #>
    function Get-DisksInternal
    {
        param (
            [Parameter(Mandatory = $false)]
            [String]
            $DiskId
        )
    
        Remove-Module Storage -ErrorAction Ignore; # Remove the Storage module to prevent it from automatically localizing
    
        $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
        if ($isDownlevel)
        {
            $disks = Get-CimInstance -ClassName MSFT_Disk -Namespace Root\Microsoft\Windows\Storage | Where-Object { !$_.IsClustered };
        }
        else
        {
            $subsystem = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace Root\Microsoft\Windows\Storage| Where-Object { $_.FriendlyName -like "Win*" };
            $disks = $subsystem | Get-CimAssociatedInstance -ResultClassName MSFT_Disk;
        }
    
        if ($DiskId)
        {
            $disks = $disks | Where-Object { $_.UniqueId -eq $DiskId };
        }
    
    
        $disks | %{
        $partitions = $_ | Get-CimAssociatedInstance -ResultClassName MSFT_Partition
        $volumes = $partitions | Get-CimAssociatedInstance -ResultClassName MSFT_Volume
        $volumeIds = @()
        $volumes | %{
            
            $volumeIds += $_.path 
        }
            
        $_ | Add-Member -NotePropertyName VolumeIds -NotePropertyValue $volumeIds
    
        }
    
        $disks = $disks | ForEach-Object {
    
           $disk = @{
                AllocatedSize = $_.AllocatedSize;
                BootFromDisk = $_.BootFromDisk;
                BusType = $_.BusType;
                FirmwareVersion = $_.FirmwareVersion;
                FriendlyName = $_.FriendlyName;
                HealthStatus = $_.HealthStatus;
                IsBoot = $_.IsBoot;
                IsClustered = $_.IsClustered;
                IsOffline = $_.IsOffline;
                IsReadOnly = $_.IsReadOnly;
                IsSystem = $_.IsSystem;
                LargestFreeExtent = $_.LargestFreeExtent;
                Location = $_.Location;
                LogicalSectorSize = $_.LogicalSectorSize;
                Model = $_.Model;
                NumberOfPartitions = $_.NumberOfPartitions;
                OfflineReason = $_.OfflineReason;
                OperationalStatus = $_.OperationalStatus;
                PartitionStyle = $_.PartitionStyle;
                Path = $_.Path;
                PhysicalSectorSize = $_.PhysicalSectorSize;
                ProvisioningType = $_.ProvisioningType;
                SerialNumber = $_.SerialNumber;
                Signature = $_.Signature;
                Size = $_.Size;
                UniqueId = $_.UniqueId;
                UniqueIdFormat = $_.UniqueIdFormat;
                volumeIds = $_.volumeIds;
                Number = $_.Number;
            }
            if (-not $isDownLevel)
            {
                $disk.IsHighlyAvailable = $_.IsHighlyAvailable;
                $disk.IsScaleOut = $_.IsScaleOut;
            }
            return $disk;
        }
    
        if ($isDownlevel)
        {
            $healthStatusMap = @{
                0 = 3;
                1 = 0;
                4 = 1;
                8 = 2;
            };
    
            $operationalStatusMap = @{
                0 = @(0);      # Unknown
                1 = @(53264);  # Online
                2 = @(53265);  # Not ready
                3 = @(53266);  # No media
                4 = @(53267);  # Offline
                5 = @(53268);  # Error
                6 = @(13);     # Lost communication
            };
    
            $disks = $disks | ForEach-Object {
                $_.HealthStatus = $healthStatusMap[[int32]$_.HealthStatus];
                $_.OperationalStatus = $operationalStatusMap[[int32]$_.OperationalStatus[0]];
                $_;
            };
        }
    
        return $disks;
    }
    
    if ($DiskId)
    {
        Get-DisksInternal -DiskId $DiskId
    }
    else
    {
        Get-DisksInternal
    }
    
}


<#
    
    .SYNOPSIS
        Enumerates all of the local file shares of the system.
    
    .DESCRIPTION
        Enumerates all of the local file shares of the system.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
    .PARAMETER FileShareId
        This parameter is OPTIONAL.    

        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-StorageFileShare

#>
function Get-StorageFileShare {
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $FileShareId
    )
    
    Import-Module CimCmdlets
    
    <#
    .Synopsis
        Name: Get-FileShares-Internal
        Description: Gets all the local file shares of the machine.
    
    .Parameters
        $FileShareId: The unique identifier of the file share desired (Optional - for cases where only one file share is desired).
    
    .Returns
        The local file share(s).
    #>
    function Get-FileSharesInternal
    {
        param (
            [Parameter(Mandatory = $false)]
            [String]
            $FileShareId
        )
    
        Remove-Module Storage -ErrorAction Ignore; # Remove the Storage module to prevent it from automatically localizing
    
        $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
        if ($isDownlevel)
        {
            # Map downlevel status to array of [health status, operational status, share state] uplevel equivalent
            $statusMap = @{
                "OK" =         @(0, 2, 1);
                "Error" =      @(2, 6, 2);
                "Degraded" =   @(1, 3, 2);
                "Unknown" =    @(5, 0, 0);
                "Pred Fail" =  @(1, 5, 2);
                "Starting" =   @(1, 8, 0);
                "Stopping" =   @(1, 9, 0);
                "Service" =    @(1, 11, 1);
                "Stressed" =   @(1, 4, 1);
                "NonRecover" = @(2, 7, 2);
                "No Contact" = @(2, 12, 2);
                "Lost Comm" =  @(2, 13, 2);
            };
            
            $shares = Get-CimInstance -ClassName Win32_Share |
                ForEach-Object {
                    return @{
                        ContinuouslyAvailable = $false;
                        Description = $_.Description;
                        EncryptData = $false;
                        FileSharingProtocol = 3;
                        HealthStatus = $statusMap[$_.Status][0];
                        IsHidden = $_.Name.EndsWith("`$");
                        Name = $_.Name;
                        OperationalStatus = ,@($statusMap[$_.Status][1]);
                        ShareState = $statusMap[$_.Status][2];
                        UniqueId = "smb|" + (Get-CimInstance Win32_ComputerSystem).DNSHostName + "." + (Get-CimInstance Win32_ComputerSystem).Domain + "\" + $_.Name;
                        VolumePath = $_.Path;
                    }
                }
        }
        else
        {        
            $shares = Get-CimInstance -ClassName MSFT_FileShare -Namespace Root\Microsoft\Windows/Storage |
                ForEach-Object {
                    return @{
                        IsHidden = $_.Name.EndsWith("`$");
                        VolumePath = $_.VolumeRelativePath;
                        ContinuouslyAvailable = $_.ContinuouslyAvailable;
                        Description = $_.Description;
                        EncryptData = $_.EncryptData;
                        FileSharingProtocol = $_.FileSharingProtocol;
                        HealthStatus = $_.HealthStatus;
                        Name = $_.Name;
                        OperationalStatus = $_.OperationalStatus;
                        UniqueId = $_.UniqueId;
                        ShareState = $_.ShareState;
                    }
                }
        }
    
        if ($FileShareId)
        {
            $shares = $shares | Where-Object { $_.UniqueId -eq $FileShareId };
        }
    
        return $shares;
    }
    
    if ($FileShareId)
    {
        Get-FileSharesInternal -FileShareId $FileShareId;
    }
    else
    {
        Get-FileSharesInternal;
    }
    
}


<#
    
    .SYNOPSIS
        Enumerates all of the local volumes of the system.
    
    .DESCRIPTION
        Enumerates all of the local volumes of the system.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
    .PARAMETER VolumeId
        This parameter is OPTIONAL.
        
        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-StorageVolume
    
#>
function Get-StorageVolume {
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $VolumeId
    )
    
    ############################################################################################################################
    
    # Global settings for the script.
    
    ############################################################################################################################
    
    $ErrorActionPreference = "Stop"
    
    Set-StrictMode -Version 3.0
    
    Import-Module CimCmdlets
    Import-Module Microsoft.PowerShell.Management
    Import-Module Microsoft.PowerShell.Utility
    Import-Module Storage
    
    ############################################################################################################################
    
    # Helper functions.
    
    ############################################################################################################################
    
    <# 
    .Synopsis
        Name: Get-VolumePathToPartition
        Description: Gets the list of partitions (that have volumes) in hashtable where key is volume path.
    
    .Returns
        The list of partitions (that have volumes) in hashtable where key is volume path.
    #>
    function Get-VolumePathToPartition
    {
        $volumePaths = @{}
    
        foreach($partition in Get-Partition)
        {
            foreach($volumePath in @($partition.AccessPaths))
            {
                if($volumePath -and (-not $volumePaths.Contains($volumePath)))
                {
                    $volumePaths.Add($volumePath, $partition)
                }
            }
        }
        
        $volumePaths
    }
    
    <# 
    .Synopsis
        Name: Get-DiskIdToDisk
        Description: Gets the list of all the disks in hashtable where key is:
                     "Disk.Path" in case of WS2016 and above.
                     OR
                     "Disk.ObjectId" in case of WS2012 and WS2012R2.
    
    .Returns
        The list of partitions (that have volumes) in hashtable where key is volume path.
    #>
    function Get-DiskIdToDisk
    {    
        $diskIds = @{}
    
        $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
    
        # In downlevel Operating systems. MSFT_Partition.DiskId is equal to MSFT_Disk.ObjectId
        # However, In WS2016 and above,   MSFT_Partition.DiskId is equal to MSFT_Disk.Path
    
        foreach($disk in Get-Disk)
        {
            if($isDownlevel)
            {
                $diskId = $disk.ObjectId
            }
            else
            {
                $diskId = $disk.Path
            }
    
            if(-not $diskIds.Contains($diskId))
            {
                $diskIds.Add($diskId, $disk)
            }
        }
    
        return $diskIds
    }
    
    <# 
    .Synopsis
        Name: Get-VolumeWs2016AndAboveOS
        Description: Gets the list of all applicable volumes from WS2012 and Ws2012R2 Operating Systems.
                     
    .Returns
        The list of all applicable volumes
    #>
    function Get-VolumeDownlevelOS
    {
        $volumes = @()
        
        foreach($volume in (Get-WmiObject -Class MSFT_Volume -Namespace root/Microsoft/Windows/Storage))
        {
           $partition = $script:partitions.Get_Item($volume.Path)
    
           # Check if this volume is associated with a partition.
           if($partition)
           {
                # If this volume is associated with a partition, then get the disk to which this partition belongs.
                $disk = $script:disks.Get_Item($partition.DiskId)
    
                # If the disk is a clustered disk then simply ignore this volume.
                if($disk -and $disk.IsClustered) {continue}
           }
      
           $volumes += $volume
        }
    
        $volumes
    }
    
    <# 
    .Synopsis
        Name: Get-VolumeWs2016AndAboveOS
        Description: Gets the list of all applicable volumes from WS2016 and above Operating System.
                     
    .Returns
        The list of all applicable volumes
    #>
    function Get-VolumeWs2016AndAboveOS
    {
        $volumes = @()
        
        $applicableVolumePaths = @{}
    
        $subSystem = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace root/Microsoft/Windows/Storage| Where-Object { $_.FriendlyName -like "Win*" }
    
        foreach($volume in @($subSystem | Get-CimAssociatedInstance -ResultClassName MSFT_Volume))
        {
            if(-not $applicableVolumePaths.Contains($volume.Path))
            {
                $applicableVolumePaths.Add($volume.Path, $null)
            }
        }
    
        foreach($volume in (Get-WmiObject -Class MSFT_Volume -Namespace root/Microsoft/Windows/Storage))
        {
            if(-not $applicableVolumePaths.Contains($volume.Path)) { continue }
    
            $volumes += $volume
        }
    
        $volumes
    }
    
    <# 
    .Synopsis
        Name: Get-VolumesList
        Description: Gets the list of all applicable volumes w.r.t to the target Operating System.
                     
    .Returns
        The list of all applicable volumes.
    #>
    function Get-VolumesList
    {
        $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
    
        if($isDownlevel)
        {
             return Get-VolumeDownlevelOS
        }
    
        Get-VolumeWs2016AndAboveOS
    }
    
    ############################################################################################################################
    
    # Helper Variables
    
    ############################################################################################################################
    
    $script:fixedDriveType = 3
    
    $script:disks = Get-DiskIdToDisk
    
    $script:partitions = Get-VolumePathToPartition
    
    ############################################################################################################################
    
    # Main script.
    
    ############################################################################################################################
    
    $resultantVolumes = @()
    
    $volumes = Get-VolumesList
    
    foreach($volume in $volumes)
    {
        $partition = $script:partitions.Get_Item($volume.Path)
    
        if($partition -and $volume.DriveType -eq $script:fixedDriveType)
        {
            $volume | Add-Member -NotePropertyName IsSystem -NotePropertyValue $partition.IsSystem
            $volume | Add-Member -NotePropertyName IsBoot -NotePropertyValue $partition.IsBoot
            $volume | Add-Member -NotePropertyName IsActive -NotePropertyValue $partition.IsActive
            $volume | Add-Member -NotePropertyName PartitionNumber -NotePropertyValue $partition.PartitionNumber
            $volume | Add-Member -NotePropertyName DiskNumber -NotePropertyValue $partition.DiskNumber
    
        }
        else
        {
            # This volume is not associated with partition, as such it is representing devices like CD-ROM, Floppy drive etc.
            $volume | Add-Member -NotePropertyName IsSystem -NotePropertyValue $true
            $volume | Add-Member -NotePropertyName IsBoot -NotePropertyValue $true
            $volume | Add-Member -NotePropertyName IsActive -NotePropertyValue $true
            $volume | Add-Member -NotePropertyName PartitionNumber -NotePropertyValue -1
            $volume | Add-Member -NotePropertyName DiskNumber -NotePropertyValue -1
        }
           
        $resultantVolumes += $volume
    }
    
    $resultantVolumes | % {
        [String] $name = '';
     
        # On the downlevel OS, the drive letter is showing charachter. The ASCII code for that char is 0.
        # So rather than checking null or empty, code is checking the ASCII code of the drive letter and updating 
        # the drive letter field to null explicitly to avoid discrepencies on UI.
        if ($_.FileSystemLabel -and [byte]$_.DriveLetter -ne 0 ) 
        { 
             $name = $_.FileSystemLabel + " (" + $_.DriveLetter + ":)"
        } 
        elseif (!$_.FileSystemLabel -and [byte]$_.DriveLetter -ne 0 ) 
        { 
              $name =  "(" + $_.DriveLetter + ":)" 
        }
        elseif ($_.FileSystemLabel -and [byte]$_.DriveLetter -eq 0)
        {
             $name = $_.FileSystemLabel
        }
        else 
        {
             $name = ''
        }
    
        if ([byte]$_.DriveLetter -eq 0)
        {
            $_.DriveLetter = $null
        }
    
        $_ | Add-Member -Force -NotePropertyName "Name" -NotePropertyValue $name
          
    }
    
    $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
    $resultantVolumes = $resultantVolumes | ForEach-Object {
    
    $volume = @{
            Name = $_.Name;
            DriveLetter = $_.DriveLetter;
            HealthStatus = $_.HealthStatus;
            DriveType = $_.DriveType;
            FileSystem = $_.FileSystem;
            FileSystemLabel = $_.FileSystemLabel;
            Path = $_.Path;
            PartitionNumber = $_.PartitionNumber;
            DiskNumber = $_.DiskNumber;
            Size = $_.Size;
            SizeRemaining = $_.SizeRemaining;
            IsSystem = $_.IsSystem;
            IsBoot = $_.IsBoot;
            IsActive = $_.IsActive;
        }
    
    if ($isDownlevel)
    {
        $volume.FileSystemType = $_.FileSystem;
    } 
    else {
    
        $volume.FileSystemType = $_.FileSystemType;
        $volume.OperationalStatus = $_.OperationalStatus;
        $volume.HealthStatus = $_.HealthStatus;
        $volume.DriveType = $_.DriveType;
        $volume.DedupMode = $_.DedupMode;
        $volume.UniqueId = $_.UniqueId;
        $volume.AllocationUnitSize = $_.AllocationUnitSize;
      
       }
    
       return $volume;
    }                                    
    
    #
    # Return results back to the caller.
    #
    if($VolumeId)
    {
        $resultantVolumes  | Where-Object {$_.Path -eq $resultantVolumes}
    }
    else
    {
        $resultantVolumes   
    }
    
    
}


<#
    
    .SYNOPSIS
        Get Windows Update History.
    
    .DESCRIPTION
        See .SYNOPSIS

    .NOTES
        From: https://stackoverflow.com/a/41626130

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-WuaHistory
    
#>
function Get-WuaHistory {
    #region >> Helper Functions

    function Convert-WuaResultCodeToName {
        param(
            [Parameter(Mandatory=$True)]
            [int]$ResultCode
        )
    
        $Result = $ResultCode
        switch($ResultCode) {
          2 {$Result = "Succeeded"}
          3 {$Result = "Succeeded With Errors"}
          4 {$Result = "Failed"}
        }
    
        return $Result
    }

    #endregion >> Helper Functions

    # Get a WUA Session
    $session = (New-Object -ComObject 'Microsoft.Update.Session')

    # Query the latest 1000 History starting with the first recordp     
    $history = $session.QueryHistory("",0,1000) | foreach {
        $Result = Convert-WuaResultCodeToName -ResultCode $_.ResultCode

        # Make the properties hidden in com properties visible.
        $_ | Add-Member -MemberType NoteProperty -Value $Result -Name Result
        $Product = $_.Categories | Where-Object {$_.Type -eq 'Product'} | Select-Object -First 1 -ExpandProperty Name
        $_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.UpdateId -Name UpdateId
        $_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.RevisionNumber -Name RevisionNumber
        $_ | Add-Member -MemberType NoteProperty -Value $Product -Name Product -PassThru

        Write-Output $_
    } 

    #Remove null records and only return the fields we want
    $history | Where-Object {![String]::IsNullOrWhiteSpace($_.title)}
}


<#
    
    .SYNOPSIS
        Installs .Net 4.7.2
    
    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER DownloadDirectory
        This parameter is OPTIONAL.

        This parameter takes a string that represents the full path to the directory that will contain the installation .exe download.

    .PARAMETER Restart
        This parameter is OPTIONAL.

        This parameter is a switch. If uses, the localhost will restart after .Net 4.7.2 is installed

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Install-DotNet472
    
#>
function Install-DotNet472 {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [string]$DownloadDirectory,

        [Parameter(Mandatory=$False)]
        [switch]$Restart
    )

    $Net472Check = Get-ChildItem "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\" | Get-ItemPropertyValue -Name Release | ForEach-Object { $_ -ge 461808 }
    if ($Net472Check) {
        Write-Warning ".Net 4.7.2 (or higher) is already installed! Halting!"
        return
    }

    $DotNet472OfflineInstallerUrl = "https://download.microsoft.com/download/6/E/4/6E48E8AB-DC00-419E-9704-06DD46E5F81D/NDP472-KB4054530-x86-x64-AllOS-ENU.exe"
    if (!$DownloadDirectory) {$DownloadDirectory = "$HOME\Downloads"}
    $OutFilePath = "$DownloadDirectory\NDP472-KB4054530-x86-x64-AllOS-ENU.exe"

    try {
        $WebClient = [System.Net.WebClient]::new()
        $WebClient.Downloadfile($DotNet472OfflineInstallerUrl, $OutFilePath)
        $WebClient.Dispose()
    }
    catch {
        Invoke-WebRequest -Uri $DotNet472OfflineInstallerUrl -OutFile $OutFilePath
    }

    if ($Restart) {
        & "$HOME\Downloads\NDP472-KB4054530-x86-x64-AllOS-ENU.exe" /q
    }
    else {
        & "$HOME\Downloads\NDP472-KB4054530-x86-x64-AllOS-ENU.exe" /q /norestart
    }
    
    while ($(Get-Process | Where-Object {$_.Name -like "*NDP472*"})) {
        Write-Host "Installing .Net Framework 4.7.2 ..."
        Start-Sleep -Seconds 5
    }

    Write-Host ".Net Framework 4.7.2 was installed successfully!" -ForegroundColor Green

    if (!$Restart) {
        Write-Warning "You MUST restart $env:ComputerName in order to use .Net Framework 4.7.2! Please do so at your earliest convenience."
    }
}


<#
    
    .SYNOPSIS
        Creates a new environment variable specified by name, type and data.
    
    .DESCRIPTION
        Creates a new environment variable specified by name, type and data.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators

    .PARAMETER name
        This parameter is MANDATORY.

        TODO

    .PARAMETER value
        This parameter is MANDATORY.

        TODO

    .PARAMETER type
        This parameter is MANDATORY.

        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> New-EnvironmentVariable -name "TestVar" -value "TestValue" -type "User"
    
#>
function New-EnvironmentVariable {
    param(
        [Parameter(Mandatory = $True)]
        [String]
        $name,
    
        [Parameter(Mandatory = $True)]
        [String]
        $value,
    
        [Parameter(Mandatory = $True)]
        [String]
        $type
    )
    
    Set-StrictMode -Version 5.0
    
    If ([Environment]::GetEnvironmentVariable($name, $type) -eq $null) {
        return [Environment]::SetEnvironmentVariable($name, $value, $type)
    }
    Else {
        Write-Error "An environment variable of this name and type already exists."
    }
}


<#
    .SYNOPSIS
        The New-Runspace function creates a Runspace that executes the specified ScriptBlock in the background
        and posts results to a Global Variable called $global:RSSyncHash.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER RunspaceName
        This parameter is MANDATORY.

        This parameter takes a string that represents the name of the new Runspace that you are creating. The name
        is represented as a key in the $global:RSSyncHash variable called: <RunspaceName>Result

    .PARAMETER ScriptBlock
        This parameter is MANDATORY.

        This parameter takes a scriptblock that will be executed in the new Runspace.

    .PARAMETER MirrorCurrentEnv
        This parameter is OPTIONAL, however, it is set to $True by default.

        This parameter is a switch. If used, all variables, functions, and Modules that are loaded in your
        current scope will be forwarded to the new Runspace.

        You can prevent the New-Runspace function from automatically mirroring your current environment by using
        this switch like: -MirrorCurrentEnv:$False 

    .PARAMETER Wait
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the main PowerShell thread will wait for the Runsapce to return
        output before proceeeding.

    .EXAMPLE
        # Open a PowerShell Session, source the function, and -

        PS C:\Users\zeroadmin> $GetProcessResults = Get-Process

        # In the below, Runspace1 refers to your current interactive PowerShell Session...

        PS C:\Users\zeroadmin> Get-Runspace

        Id Name            ComputerName    Type          State         Availability
        -- ----            ------------    ----          -----         ------------
        1 Runspace1       localhost       Local         Opened        Busy

        # The below will create a 'Runspace Manager Runspace' (if it doesn't already exist)
        # to manage all other new Runspaces created by the New-Runspace function.
        # Additionally, it will create the Runspace that actually runs the -ScriptBlock.
        # The 'Runspace Manager Runspace' disposes of new Runspaces when they're
        # finished running.

        PS C:\Users\zeroadmin> New-RunSpace -RunSpaceName PSIds -ScriptBlock {$($GetProcessResults | Where-Object {$_.Name -eq "powershell"}).Id}

        # The 'Runspace Manager Runspace' persists just in case you create any additional
        # Runspaces, but the Runspace that actually ran the above -ScriptBlock does not.
        # In the below, 'Runspace2' is the 'Runspace Manager Runspace. 

        PS C:\Users\zeroadmin> Get-Runspace

        Id Name            ComputerName    Type          State         Availability
        -- ----            ------------    ----          -----         ------------
        1 Runspace1       localhost       Local         Opened        Busy
        2 Runspace2       localhost       Local         Opened        Busy

        # You can actively identify (as opposed to infer) the 'Runspace Manager Runspace'
        # by using one of three Global variables created by the New-Runspace function:

        PS C:\Users\zeroadmin> $global:RSJobCleanup.PowerShell.Runspace

        Id Name            ComputerName    Type          State         Availability
        -- ----            ------------    ----          -----         ------------
        2 Runspace2       localhost       Local         Opened        Busy

        # As mentioned above, the New-RunspaceName function creates three Global
        # Variables. They are $global:RSJobs, $global:RSJobCleanup, and
        # $global:RSSyncHash. Your output can be found in $global:RSSyncHash.

        PS C:\Users\zeroadmin> $global:RSSyncHash

        Name                           Value
        ----                           -----
        PSIdsResult                    @{Done=True; Errors=; Output=System.Object[]}
        ProcessedJobRecords            {@{Name=PSIdsHelper; PSInstance=System.Management.Automation.PowerShell; Runspace=System.Management.Automation.Runspaces.Loca...


        PS C:\Users\zeroadmin> $global:RSSyncHash.PSIdsResult

        Done Errors Output
        ---- ------ ------
        True        {1300, 2728, 2960, 3712...}


        PS C:\Users\zeroadmin> $global:RSSyncHash.PSIdsResult.Output
        1300
        2728
        2960
        3712
        4632

        # Important Note: You don't need to worry about passing variables / functions /
        # Modules to the Runspace. Everything in your current session/scope is
        # automatically forwarded by the New-Runspace function:

        PS C:\Users\zeroadmin> function Test-Func {'This is Test-Func output'}
        PS C:\Users\zeroadmin> New-RunSpace -RunSpaceName FuncTest -ScriptBlock {Test-Func}
        PS C:\Users\zeroadmin> $global:RSSyncHash

        Name                           Value
        ----                           -----
        FuncTestResult                 @{Done=True; Errors=; Output=This is Test-Func output}
        PSIdsResult                    @{Done=True; Errors=; Output=System.Object[]}
        ProcessedJobRecords            {@{Name=PSIdsHelper; PSInstance=System.Management.Automation.PowerShell; Runspace=System.Management.Automation.Runspaces.Loca...

        PS C:\Users\zeroadmin> $global:RSSyncHash.FuncTestResult.Output
        This is Test-Func output  
#>
function New-RunSpace {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$RunspaceName,

        [Parameter(Mandatory=$True)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory=$False)]
        [switch]$MirrorCurrentEnv = $True,

        [Parameter(Mandatory=$False)]
        [switch]$Wait
    )

    #region >> Helper Functions

    function NewUniqueString {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string[]]$ArrayOfStrings,
    
            [Parameter(Mandatory=$True)]
            [string]$PossibleNewUniqueString
        )
    
        if (!$ArrayOfStrings -or $ArrayOfStrings.Count -eq 0 -or ![bool]$($ArrayOfStrings -match "[\w]")) {
            $PossibleNewUniqueString
        }
        else {
            $OriginalString = $PossibleNewUniqueString
            $Iteration = 1
            while ($ArrayOfStrings -contains $PossibleNewUniqueString) {
                $AppendedValue = "_$Iteration"
                $PossibleNewUniqueString = $OriginalString + $AppendedValue
                $Iteration++
            }
    
            $PossibleNewUniqueString
        }
    }

    #endregion >> Helper Functions

    #region >> Runspace Prep

    # Create Global Variable Names that don't conflict with other exisiting Global Variables
    $ExistingGlobalVariables = Get-Variable -Scope Global
    $DesiredGlobalVariables = @("RSSyncHash","RSJobCleanup","RSJobs")
    if ($ExistingGlobalVariables.Name -notcontains 'RSSyncHash') {
        $GlobalRSSyncHashName = NewUniqueString -PossibleNewUniqueString "RSSyncHash" -ArrayOfStrings $ExistingGlobalVariables.Name
        Invoke-Expression "`$global:$GlobalRSSyncHashName = [hashtable]::Synchronized(@{})"
        $globalRSSyncHash = Get-Variable -Name $GlobalRSSyncHashName -Scope Global -ValueOnly
    }
    else {
        $GlobalRSSyncHashName = 'RSSyncHash'

        # Also make sure that $RunSpaceName is a unique key in $global:RSSyncHash
        if ($RSSyncHash.Keys -contains $RunSpaceName) {
            $RSNameOriginal = $RunSpaceName
            $RunSpaceName = NewUniqueString -PossibleNewUniqueString $RunSpaceName -ArrayOfStrings $RSSyncHash.Keys
            if ($RSNameOriginal -ne $RunSpaceName) {
                Write-Warning "The RunspaceName '$RSNameOriginal' already exists. Your new RunspaceName will be '$RunSpaceName'"
            }
        }

        $globalRSSyncHash = $global:RSSyncHash
    }
    if ($ExistingGlobalVariables.Name -notcontains 'RSJobCleanup') {
        $GlobalRSJobCleanupName = NewUniqueString -PossibleNewUniqueString "RSJobCleanup" -ArrayOfStrings $ExistingGlobalVariables.Name
        Invoke-Expression "`$global:$GlobalRSJobCleanupName = [hashtable]::Synchronized(@{})"
        $globalRSJobCleanup = Get-Variable -Name $GlobalRSJobCleanupName -Scope Global -ValueOnly
    }
    else {
        $GlobalRSJobCleanupName = 'RSJobCleanup'
        $globalRSJobCleanup = $global:RSJobCleanup
    }
    if ($ExistingGlobalVariables.Name -notcontains 'RSJobs') {
        $GlobalRSJobsName = NewUniqueString -PossibleNewUniqueString "RSJobs" -ArrayOfStrings $ExistingGlobalVariables.Name
        Invoke-Expression "`$global:$GlobalRSJobsName = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())"
        $globalRSJobs = Get-Variable -Name $GlobalRSJobsName -Scope Global -ValueOnly
    }
    else {
        $GlobalRSJobsName = 'RSJobs'
        $globalRSJobs = $global:RSJobs
    }
    $GlobalVariables = @($GlobalSyncHashName,$GlobalRSJobCleanupName,$GlobalRSJobsName)
    #Write-Host "Global Variable names are: $($GlobalVariables -join ", ")"

    # Prep an empty pscustomobject for the RunspaceNameResult Key in $globalRSSyncHash
    $globalRSSyncHash."$RunspaceName`Result" = [pscustomobject]@{}

    #endregion >> Runspace Prep


    ##### BEGIN Runspace Manager Runspace (A Runspace to Manage All Runspaces) #####

    $globalRSJobCleanup.Flag = $True

    if ($ExistingGlobalVariables.Name -notcontains 'RSJobCleanup') {
        #Write-Host '$global:RSJobCleanup does NOT already exists. Creating New Runspace Manager Runspace...'
        $RunspaceMgrRunspace = [runspacefactory]::CreateRunspace()
        if ($PSVersionTable.PSEdition -ne "Core") {
            $RunspaceMgrRunspace.ApartmentState = "STA"
        }
        $RunspaceMgrRunspace.ThreadOptions = "ReuseThread"
        $RunspaceMgrRunspace.Open()

        # Prepare to Receive the Child Runspace Info to the RunspaceManagerRunspace
        $RunspaceMgrRunspace.SessionStateProxy.SetVariable("JobCleanup",$globalRSJobCleanup)
        $RunspaceMgrRunspace.SessionStateProxy.SetVariable("jobs",$globalRSJobs)
        $RunspaceMgrRunspace.SessionStateProxy.SetVariable("SyncHash",$globalRSSyncHash)

        $globalRSJobCleanup.PowerShell = [PowerShell]::Create().AddScript({

            ##### BEGIN Runspace Manager Runspace Helper Functions #####

            # Load the functions we packed up
            $FunctionsForSBUse | foreach { Invoke-Expression $_ }

            ##### END Runspace Manager Runspace Helper Functions #####

            # Routine to handle completed Runspaces
            $ProcessedJobRecords = [System.Collections.ArrayList]::new()
            $SyncHash.ProcessedJobRecords = $ProcessedJobRecords
            while ($JobCleanup.Flag) {
                if ($jobs.Count -gt 0) {
                    $Counter = 0
                    foreach($job in $jobs) { 
                        if ($ProcessedJobRecords.Runspace.InstanceId.Guid -notcontains $job.Runspace.InstanceId.Guid) {
                            $job | Export-CliXml "$HOME\job$Counter.xml" -Force
                            $CollectJobRecordPrep = Import-CliXML -Path "$HOME\job$Counter.xml"
                            Remove-Item -Path "$HOME\job$Counter.xml" -Force
                            $null = $ProcessedJobRecords.Add($CollectJobRecordPrep)
                        }

                        if ($job.AsyncHandle.IsCompleted -or $job.AsyncHandle -eq $null) {
                            [void]$job.PSInstance.EndInvoke($job.AsyncHandle)
                            $job.Runspace.Dispose()
                            $job.PSInstance.Dispose()
                            $job.AsyncHandle = $null
                            $job.PSInstance = $null
                        }
                        $Counter++
                    }

                    # Determine if we can have the Runspace Manager Runspace rest
                    $temparray = $jobs.clone()
                    $temparray | Where-Object {
                        $_.AsyncHandle.IsCompleted -or $_.AsyncHandle -eq $null
                    } | foreach {
                        $temparray.remove($_)
                    }

                    <#
                    if ($temparray.Count -eq 0 -or $temparray.AsyncHandle.IsCompleted -notcontains $False) {
                        $JobCleanup.Flag = $False
                    }
                    #>

                    Start-Sleep -Seconds 5

                    # Optional -
                    # For realtime updates to a GUI depending on changes in data within the $globalRSSyncHash, use
                    # a something like the following (replace with $RSSyncHash properties germane to your project)
                    <#
                    if ($RSSyncHash.WPFInfoDatagrid.Items.Count -ne 0 -and $($RSSynchash.IPArray.Count -ne 0 -or $RSSynchash.IPArray -ne $null)) {
                        if ($RSSyncHash.WPFInfoDatagrid.Items.Count -ge $RSSynchash.IPArray.Count) {
                            Update-Window -Control $RSSyncHash.WPFInfoPleaseWaitLabel -Property Visibility -Value "Hidden"
                        }
                    }
                    #>
                }
            } 
        })

        # Start the RunspaceManagerRunspace
        $globalRSJobCleanup.PowerShell.Runspace = $RunspaceMgrRunspace
        $globalRSJobCleanup.Thread = $globalRSJobCleanup.PowerShell.BeginInvoke()
    }

    ##### END Runspace Manager Runspace #####


    ##### BEGIN New Generic Runspace #####

    $GenericRunspace = [runspacefactory]::CreateRunspace()
    if ($PSVersionTable.PSEdition -ne "Core") {
        $GenericRunspace.ApartmentState = "STA"
    }
    $GenericRunspace.ThreadOptions = "ReuseThread"
    $GenericRunspace.Open()

    # Pass the $globalRSSyncHash to the Generic Runspace so it can read/write properties to it and potentially
    # coordinate with other runspaces
    $GenericRunspace.SessionStateProxy.SetVariable("SyncHash",$globalRSSyncHash)

    # Pass $globalRSJobCleanup and $globalRSJobs to the Generic Runspace so that the Runspace Manager Runspace can manage it
    $GenericRunspace.SessionStateProxy.SetVariable("JobCleanup",$globalRSJobCleanup)
    $GenericRunspace.SessionStateProxy.SetVariable("Jobs",$globalRSJobs)
    $GenericRunspace.SessionStateProxy.SetVariable("ScriptBlock",$ScriptBlock)

    # Pass all other notable environment characteristics 
    if ($MirrorCurrentEnv) {
        [System.Collections.ArrayList]$SetEnvStringArray = @()

        $VariablesNotToForward = @('globalRSSyncHash','RSSyncHash','globalRSJobCleanUp','RSJobCleanup',
        'globalRSJobs','RSJobs','ExistingGlobalVariables','DesiredGlobalVariables','$GlobalRSSyncHashName',
        'RSNameOriginal','GlobalRSJobCleanupName','GlobalRSJobsName','GlobalVariables','RunspaceMgrRunspace',
        'GenericRunspace','ScriptBlock')

        $Variables = Get-Variable
        foreach ($VarObj in $Variables) {
            if ($VariablesNotToForward -notcontains $VarObj.Name) {
                try {
                    $GenericRunspace.SessionStateProxy.SetVariable($VarObj.Name,$VarObj.Value)
                }
                catch {
                    Write-Verbose "Skipping `$$($VarObj.Name)..."
                }
            }
        }

        # Set Environment Variables
        $EnvVariables = Get-ChildItem Env:\
        if ($PSBoundParameters['EnvironmentVariablesToForward'] -and $EnvironmentVariablesToForward -notcontains '*') {
            $EnvVariables = foreach ($VarObj in $EnvVariables) {
                if ($EnvironmentVariablesToForward -contains $VarObj.Name) {
                    $VarObj
                }
            }
        }
        $SetEnvVarsPrep = foreach ($VarObj in $EnvVariables) {
            if ([char[]]$VarObj.Name -contains '(' -or [char[]]$VarObj.Name -contains ' ') {
                $EnvStringArr = @(
                    'try {'
                    $('    ${env:' + $VarObj.Name + '} = ' + "@'`n$($VarObj.Value)`n'@")
                    '}'
                    'catch {'
                    "    Write-Verbose 'Unable to forward environment variable $($VarObj.Name)'"
                    '}'
                )
            }
            else {
                $EnvStringArr = @(
                    'try {'
                    $('    $env:' + $VarObj.Name + ' = ' + "@'`n$($VarObj.Value)`n'@")
                    '}'
                    'catch {'
                    "    Write-Verbose 'Unable to forward environment variable $($VarObj.Name)'"
                    '}'
                )
            }
            $EnvStringArr -join "`n"
        }
        $SetEnvVarsString = $SetEnvVarsPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetEnvVarsString)

        # Set Modules
        $Modules = Get-Module
        if ($PSBoundParameters['ModulesToForward'] -and $ModulesToForward -notcontains '*') {
            $Modules = foreach ($ModObj in $Modules) {
                if ($ModulesToForward -contains $ModObj.Name) {
                    $ModObj
                }
            }
        }

        $ModulesNotToForward = @('MiniLab')

        $SetModulesPrep = foreach ($ModObj in $Modules) {
            if ($ModulesNotToForward -notcontains $ModObj.Name) {
                $ModuleManifestFullPath = $(Get-ChildItem -Path $ModObj.ModuleBase -Recurse -File | Where-Object {
                    $_.Name -eq "$($ModObj.Name).psd1"
                }).FullName

                $ModStringArray = @(
                    '$tempfile = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())'
                    "if (![bool]('$($ModObj.Name)' -match '\.WinModule')) {"
                    '    try {'
                    "        Import-Module '$($ModObj.Name)' -NoClobber -ErrorAction Stop 2>`$tempfile"
                    '    }'
                    '    catch {'
                    '        try {'
                    "            Import-Module '$ModuleManifestFullPath' -NoClobber -ErrorAction Stop 2>`$tempfile"
                    '        }'
                    '        catch {'
                    "            Write-Warning 'Unable to Import-Module $($ModObj.Name)'"
                    '        }'
                    '    }'
                    '}'
                    'if (Test-Path $tempfile) {'
                    '    Remove-Item $tempfile -Force'
                    '}'
                )
                $ModStringArray -join "`n"
            }
        }
        $SetModulesString = $SetModulesPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetModulesString)
    
        # Set Functions
        $Functions = Get-ChildItem Function:\ | Where-Object {![System.String]::IsNullOrWhiteSpace($_.Name)}
        if ($PSBoundParameters['FunctionsToForward'] -and $FunctionsToForward -notcontains '*') {
            $Functions = foreach ($FuncObj in $Functions) {
                if ($FunctionsToForward -contains $FuncObj.Name) {
                    $FuncObj
                }
            }
        }
        $SetFunctionsPrep = foreach ($FuncObj in $Functions) {
            $FunctionText = Invoke-Expression $('@(${Function:' + $FuncObj.Name + '}.Ast.Extent.Text)')
            if ($($FunctionText -split "`n").Count -gt 1) {
                if ($($FunctionText -split "`n")[0] -match "^function ") {
                    if ($($FunctionText -split "`n") -match "^'@") {
                        Write-Warning "Unable to forward function $($FuncObj.Name) due to heredoc string: '@"
                    }
                    else {
                        'Invoke-Expression ' + "@'`n$FunctionText`n'@"
                    }
                }
            }
            elseif ($($FunctionText -split "`n").Count -eq 1) {
                if ($FunctionText -match "^function ") {
                    'Invoke-Expression ' + "@'`n$FunctionText`n'@"
                }
            }
        }
        $SetFunctionsString = $SetFunctionsPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetFunctionsString)

        $GenericRunspace.SessionStateProxy.SetVariable("SetEnvStringArray",$SetEnvStringArray)
    }

    $GenericPSInstance = [powershell]::Create()

    # Define the main PowerShell Script that will run the $ScriptBlock
    $null = $GenericPSInstance.AddScript({
        $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Done -Value $False
        $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Errors -Value $null
        $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name ErrorsDetailed -Value $null
        $SyncHash."$RunspaceName`Result".Errors = [System.Collections.ArrayList]::new()
        $SyncHash."$RunspaceName`Result".ErrorsDetailed = [System.Collections.ArrayList]::new()
        $SyncHash."$RunspaceName`Result" | Add-Member -Type NoteProperty -Name ThisRunspace -Value $($(Get-Runspace)[-1])
        [System.Collections.ArrayList]$LiveOutput = @()
        $SyncHash."$RunspaceName`Result" | Add-Member -Type NoteProperty -Name LiveOutput -Value $LiveOutput
        $SyncHash."$RunspaceName`Result" | Add-Member -Type NoteProperty -Name ScriptBeingRun -Value $ScriptBlock
        

        
        ##### BEGIN Generic Runspace Helper Functions #####

        # Load the environment we packed up
        if ($SetEnvStringArray) {
            foreach ($obj in $SetEnvStringArray) {
                if (![string]::IsNullOrWhiteSpace($obj)) {
                    try {
                        Invoke-Expression $obj
                    }
                    catch {
                        $null = $SyncHash."$RunSpaceName`Result".Errors.Add($_)

                        $ErrMsg = "Problem with:`n$obj`nError Message:`n" + $($_ | Out-String)
                        $null = $SyncHash."$RunSpaceName`Result".ErrorsDetailed.Add($ErrMsg)
                    }
                }
            }
        }

        ##### END Generic Runspace Helper Functions #####

        ##### BEGIN Script To Run #####

        try {
            # NOTE: Depending on the content of the scriptblock, InvokeReturnAsIs() and Invoke-Command can cause
            # the Runspace to hang. Invoke-Expression works all the time.
            #$Result = $ScriptBlock.InvokeReturnAsIs()
            #$Result = Invoke-Command -ScriptBlock $ScriptBlock
            #$SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name SBString -Value $ScriptBlock.ToString()
            Invoke-Expression -Command $ScriptBlock.ToString() -OutVariable Result
            $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Output -Value $Result
        }
        catch {
            $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Output -Value $Result

            $null = $SyncHash."$RunSpaceName`Result".Errors.Add($_)

            $ErrMsg = "Problem with:`n$($ScriptBlock.ToString())`nError Message:`n" + $($_ | Out-String)
            $null = $SyncHash."$RunSpaceName`Result".ErrorsDetailed.Add($ErrMsg)
        }

        ##### END Script To Run #####

        $SyncHash."$RunSpaceName`Result".Done = $True
    })

    # Start the Generic Runspace
    $GenericPSInstance.Runspace = $GenericRunspace

    if ($Wait) {
        # The below will make any output of $GenericRunspace available in $Object in current scope
        $Object = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
        $GenericAsyncHandle = $GenericPSInstance.BeginInvoke($Object,$Object)

        $GenericRunspaceInfo = [pscustomobject]@{
            Name            = $RunSpaceName + "Generic"
            PSInstance      = $GenericPSInstance
            Runspace        = $GenericRunspace
            AsyncHandle     = $GenericAsyncHandle
        }
        $null = $globalRSJobs.Add($GenericRunspaceInfo)

        #while ($globalRSSyncHash."$RunSpaceName`Done" -ne $True) {
        while ($GenericAsyncHandle.IsCompleted -ne $True) {
            #Write-Host "Waiting for -ScriptBlock to finish..."
            Start-Sleep -Milliseconds 10
        }

        $globalRSSyncHash."$RunspaceName`Result".Output
        #$Object
    }
    else {
        $HelperRunspace = [runspacefactory]::CreateRunspace()
        if ($PSVersionTable.PSEdition -ne "Core") {
            $HelperRunspace.ApartmentState = "STA"
        }
        $HelperRunspace.ThreadOptions = "ReuseThread"
        $HelperRunspace.Open()

        # Pass the $globalRSSyncHash to the Helper Runspace so it can read/write properties to it and potentially
        # coordinate with other runspaces
        $HelperRunspace.SessionStateProxy.SetVariable("SyncHash",$globalRSSyncHash)

        # Pass $globalRSJobCleanup and $globalRSJobs to the Helper Runspace so that the Runspace Manager Runspace can manage it
        $HelperRunspace.SessionStateProxy.SetVariable("JobCleanup",$globalRSJobCleanup)
        $HelperRunspace.SessionStateProxy.SetVariable("Jobs",$globalRSJobs)

        # Set any other needed variables in the $HelperRunspace
        $HelperRunspace.SessionStateProxy.SetVariable("GenericRunspace",$GenericRunspace)
        $HelperRunspace.SessionStateProxy.SetVariable("GenericPSInstance",$GenericPSInstance)
        $HelperRunspace.SessionStateProxy.SetVariable("RunSpaceName",$RunSpaceName)

        $HelperPSInstance = [powershell]::Create()

        # Define the main PowerShell Script that will run the $ScriptBlock
        $null = $HelperPSInstance.AddScript({
            ##### BEGIN Script To Run #####

            # The below will make any output of $GenericRunspace available in $Object in current scope
            $Object = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
            $GenericAsyncHandle = $GenericPSInstance.BeginInvoke($Object,$Object)

            $GenericRunspaceInfo = [pscustomobject]@{
                Name            = $RunSpaceName + "Generic"
                PSInstance      = $GenericPSInstance
                Runspace        = $GenericRunspace
                AsyncHandle     = $GenericAsyncHandle
            }
            $null = $Jobs.Add($GenericRunspaceInfo)

            #while ($SyncHash."$RunSpaceName`Done" -ne $True) {
            while ($GenericAsyncHandle.IsCompleted -ne $True) {
                #Write-Host "Waiting for -ScriptBlock to finish..."
                Start-Sleep -Milliseconds 10
            }

            ##### END Script To Run #####
        })

        # Start the Helper Runspace
        $HelperPSInstance.Runspace = $HelperRunspace
        $HelperAsyncHandle = $HelperPSInstance.BeginInvoke()

        $HelperRunspaceInfo = [pscustomobject]@{
            Name            = $RunSpaceName + "Helper"
            PSInstance      = $HelperPSInstance
            Runspace        = $HelperRunspace
            AsyncHandle     = $HelperAsyncHandle
        }
        $null = $globalRSJobs.Add($HelperRunspaceInfo)
    }

    ##### END Generic Runspace
}


<#
    .SYNOPSIS
        Removes an environment variable specified by name and type.
    
    .DESCRIPTION
        Removes an environment variable specified by name and type.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators

    .PARAMETER name
        This parameter is MANDATORY.

        TODO

    .PARAMETER type
        This parameter is MANDATORY.

        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Remove-EnvironmentVariable -name "TestVar" -type "User"
    
#>
function Remove-EnvironmentVariable {
    param(
        [Parameter(Mandatory = $True)]
        [String]
        $name,
    
        [Parameter(Mandatory = $True)]
        [String]
        $type
    )
    
    Set-StrictMode -Version 5.0
    
    If ([Environment]::GetEnvironmentVariable($name, $type) -eq $null) {
        Write-Error "An environment variable of this name and type does not exist."
    }
    Else {
        [Environment]::SetEnvironmentVariable($name, $null, $type)
    }
}


<#
    
    .SYNOPSIS
        Sets a computer and/or its domain/workgroup information.
    
    .DESCRIPTION
        Sets a computer and/or its domain/workgroup information.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators

    .PARAMETER ComputerName
        This parameter is OPTIONAL.

        TODO

    .PARAMETER NewComputerName
        This parameter is OPTIONAL.

        TODO

    .PARAMETER Domain
        This parameter is OPTIONAL.

        TODO

    .PARAMETER NewDomain
        This parameter is OPTIONAL.

        TODO

    .PARAMETER Workgroup
        This parameter is OPTIONAL.

        TODO

    .PARAMETER UserName
        This parameter is OPTIONAL.

        TODO

    .PARAMETER Password
        This parameter is OPTIONAL.

        TODO

    .PARAMETER UserNameNew
        This parameter is OPTIONAL.

        TODO

    .PARAMETER PasswordNew
        This parameter is OPTIONAL.

        TODO

    .PARAMETER Restart
        This parameter is OPTIONAL.

        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Set-ComputerIdentification -ComputerName $env:ComputerName -NewComputerName "SQLServer01"
    
#>
function Set-ComputerIdentification {
    param(
        [Parameter(Mandatory = $False)]
        [string]
        $ComputerName = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $NewComputerName = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $Domain = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $NewDomain = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $Workgroup = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $UserName = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $Password = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $UserNameNew = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $PasswordNew = '',
    
        [Parameter(Mandatory = $False)]
        [switch]
        $Restart)
    
    function CreateDomainCred($username, $password) {
        $secureString = ConvertTo-SecureString $password -AsPlainText -Force
        $domainCreds = New-Object System.Management.Automation.PSCredential($username, $secureString)
    
        return $domainCreds
    }
    
    function UnjoinDomain($domain) {
        If ($domain) {
            $unjoinCreds = CreateDomainCred $UserName $Password
            Remove-Computer -UnjoinDomainCredential $unjoinCreds -PassThru -Force
        }
    }
    
    If ($NewDomain) {
        $newDomainCreds = $null
        If ($Domain) {
            UnjoinDomain $Domain
            $newDomainCreds = CreateDomainCred $UserNameNew $PasswordNew
        }
        else {
            $newDomainCreds = CreateDomainCred $UserName $Password
        }
    
        If ($NewComputerName) {
            Add-Computer -ComputerName $ComputerName -DomainName $NewDomain -Credential $newDomainCreds -Force -PassThru -NewName $NewComputerName -Restart:$Restart
        }
        Else {
            Add-Computer -ComputerName $ComputerName -DomainName $NewDomain -Credential $newDomainCreds -Force -PassThru -Restart:$Restart
        }
    }
    ElseIf ($Workgroup) {
        UnjoinDomain $Domain
    
        If ($NewComputerName) {
            Add-Computer -WorkGroupName $Workgroup -Force -PassThru -NewName $NewComputerName -Restart:$Restart
        }
        Else {
            Add-Computer -WorkGroupName $Workgroup -Force -PassThru -Restart:$Restart
        }
    }
    ElseIf ($NewComputerName) {
        If ($Domain) {
            $domainCreds = CreateDomainCred $UserName $Password
            Rename-Computer -NewName $NewComputerName -DomainCredential $domainCreds -Force -PassThru -Restart:$Restart
        }
        Else {
            Rename-Computer -NewName $NewComputerName -Force -PassThru -Restart:$Restart
        }
    }
}


<#
    
    .SYNOPSIS
        Updates or renames an environment variable specified by name, type, data and previous data.
    
    .DESCRIPTION
        Updates or Renames an environment variable specified by name, type, data and previrous data.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators

    .PARAMETER oldName
        This parameter is MANDATORY.

        TODO

    .PARAMETER newName
        This parameter is MANDATORY.

        TODO

    .PARAMETER value
        This parameter is MANDATORY.

        TODO

    .PARAMETER type
        This parameter is MANDATORY.

        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Set-EnvironmentVariable -oldName "OldVar" -newName "NewVar" -value "thing1" -type "User"
    
#>
function Set-EnvironmentVariable {
    param(
        [Parameter(Mandatory = $True)]
        [String]
        $oldName,
    
        [Parameter(Mandatory = $True)]
        [String]
        $newName,
    
        [Parameter(Mandatory = $True)]
        [String]
        $value,
    
        [Parameter(Mandatory = $True)]
        [String]
        $type
    )
    
    Set-StrictMode -Version 5.0
    
    $nameChange = $false
    if ($newName -ne $oldName) {
        $nameChange = $true
    }
    
    If (-not [Environment]::GetEnvironmentVariable($oldName, $type)) {
        @{ Status = "currentMissing" }
        return
    }
    
    If ($nameChange -and [Environment]::GetEnvironmentVariable($newName, $type)) {
        @{ Status = "targetConflict" }
        return
    }
    
    If ($nameChange) {
        [Environment]::SetEnvironmentVariable($oldName, $null, $type)
        [Environment]::SetEnvironmentVariable($newName, $value, $type)
        @{ Status = "success" }
    }
    Else {
        [Environment]::SetEnvironmentVariable($newName, $value, $type)
        @{ Status = "success" }
    }    
}


<#
    
    .SYNOPSIS
        Sets a computer's remote desktop settings.
    
    .DESCRIPTION
        Sets a computer's remote desktop settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators

    .PARAMETER AllowRemoteDesktop
        This parameter is OPTIONAL.

        TODO

    .PARAMETER AllowRemoteDesktopWithNLA
        This parameter is OPTIONAL.

        TODO

    .PARAMETER EnableRemoteApp
        This parameter is OPTIONAL.

        TODO

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Set-RemoteDesktop -AllowRemoteDesktop
    
#>
function Set-RemoteDesktop {
    param(
        [Parameter(Mandatory = $False)]
        [boolean]
        $AllowRemoteDesktop,
        
        [Parameter(Mandatory = $False)]
        [boolean]
        $AllowRemoteDesktopWithNLA,
        
        [Parameter(Mandatory=$False)]
        [boolean]
        $EnableRemoteApp)
    
    Import-Module NetSecurity
    Import-Module Microsoft.PowerShell.Management
        
    $regKey1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $regKey2 = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    
    $keyProperty1 = "fDenyTSConnections"
    $keyProperty2 = "UserAuthentication"
    $keyProperty3 = "EnableRemoteApp"
    
    $keyPropertyValue1 = $(if ($AllowRemoteDesktop -eq $True) { 0 } else { 1 })
    $keyPropertyValue2 = $(if ($AllowRemoteDesktopWithNLA -eq $True) { 1 } else { 0 })
    $keyPropertyValue3 = $(if ($EnableRemoteApp -eq $True) { 1 } else { 0 })
    
    if (!(Test-Path $regKey1)) {
        New-Item -Path $regKey1 -Force | Out-Null
    }
    
    New-ItemProperty -Path $regKey1 -Name $keyProperty1 -Value $keyPropertyValue1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $regKey1 -Name $keyProperty3 -Value $keyPropertyValue3 -PropertyType DWORD -Force | Out-Null
    
    if (!(Test-Path $regKey2)) {
        New-Item -Path $regKey2 -Force | Out-Null
    }
    
    New-ItemProperty -Path $regKey2 -Name $keyProperty2 -Value $keyPropertyValue2 -PropertyType DWORD -Force | Out-Null
    
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
}


<#
    
    .SYNOPSIS
        Start Disk Performance monitoring.
    
    .DESCRIPTION
        Start Disk Performance monitoring.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Start-DiskPerf
    
#>
function Start-DiskPerf {
    # Update the registry key at HKLM:SYSTEM\\CurrentControlSet\\Services\\Partmgr
    #   EnableCounterForIoctl = DWORD 3
    & diskperf -Y
}


<#
    
    .SYNOPSIS
        Stop Disk Performance monitoring.
    
    .DESCRIPTION
        Stop Disk Performance monitoring.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Stop-DiskPerf
    
#>
function Stop-DiskPerf {
    # Update the registry key at HKLM:SYSTEM\\CurrentControlSet\\Services\\Partmgr
    #   EnableCounterForIoctl = DWORD 1
    & diskperf -N
}


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



if ($PSVersionTable.Platform -eq "Win32NT" -and $PSVersionTable.PSEdition -eq "Core") {
    if (![bool]$(Get-Module -ListAvailable WindowsCompatibility)) {
        try {
            Install-Module WindowsCompatibility -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    if (![bool]$(Get-Module WindowsCompatibility)) {
        try {
            Import-Module WindowsCompatibility -ErrorAction Stop
        }
        catch {
            Write-Error $_
            Write-Warning "The $ThisModule Module was NOT loaded successfully! Please run:`n    Remove-Module $ThisModule"
            $global:FunctionResult = "1"
            return
        }
    }
}

# Can't just install and import UniversalDashboard.Community automatically because of interactive license agreement prompt. So, it must be done
# manually before trying to import PUDAdminCenter.
if (![bool]$(Get-Module -ListAvailable UniversalDashboard.Community)) {
    $InstallPUDCommunityMsg = "Please install the UniversalDashboard.Community PowerShell Module via...`n    Install-Module UniversalDashboard.Community`n..." +
    "and try importing the PUDAdminCenter Module in a fresh Windows PowerShell 5.1 session."
    Write-Warning $InstallPUDCommunityMsg
    Write-Warning "The $ThisModule Module was NOT loaded successfully! Please run:`n    Remove-Module $ThisModule"
    $global:FunctionResult = "1"
    return
}

if (![bool]$(Get-Module UniversalDashboard.Community)) {
    try {
        Import-Module UniversalDashboard.Community -ErrorAction Stop
    }
    catch {
        Write-Error $_
        Write-Warning "The $ThisModule Module was NOT loaded successfully! Please run:`n    Remove-Module $ThisModule"
        $global:FunctionResult = "1"
        return

        # The below is commented out because there's some concern about whether installing .Net 4.7.2 automatically on Module Import is a good practice
        <#
        if ($_.Exception.Message -match "\.Net Framework") {
            $Net472Check = Get-ChildItem "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\" | Get-ItemPropertyValue -Name Release | ForEach-Object { $_ -ge 461808 }

            if (!$Net472Check) {
                try {
                    Write-Host "Installing .Net Framework 4.7.2 ... This will take a little while, and you will need to restart afterwards..."
                    #$InstallDotNet47Result = Install-Program -ProgramName dotnet4.7.2 -ErrorAction Stop
                    Install-DotNet472 -DownloadDirectory "$HOME\Downloads" -ErrorAction Stop
                }
                catch {
                    Write-Error $_
                    Write-Warning ".Net Framework 4.7.2 was NOT installed successfully."
                    Write-Warning "The $ThisModule Module will NOT be loaded. Please run`n    Remove-Module $ThisModule"
                    $global:FunctionResult = "1"
                    return
                }
            }
            else {
                Write-Error $_
                Write-Warning ".Net Framework 4.7.2 is already installed! Please review the above error message before using the $ThisModule Module!"
                Write-Warning "The $ThisModule Module will NOT be loaded. Please run`n    Remove-Module $ThisModule"
                $global:FunctionResult = "1"
                return
            }

            Write-Warning ".Net Framework 4.7.2 was installed successfully, however *****you must restart $env:ComputerName***** before using the $ThisModule Module! Halting!"
            return
        }
        else {
            Write-Error $_
            Write-Warning "The $ThisModule Module was NOT loaded successfully! Please run:`n    Remove-Module $ThisModule"
            $global:FunctionResult = "1"
            return
        }
        #>
    }
}

[System.Collections.ArrayList]$script:FunctionsForSBUse = @(
    ${Function:AddWinRMTrustedHost}.Ast.Extent.Text
    ${Function:AddWinRMTrustLocalHost}.Ast.Extent.Text
    ${Function:CheckSudoStatus}.Ast.Extent.Text
    ${Function:EnableWinRMViaRPC}.Ast.Extent.Text
    ${Function:GetComputerObjectsInLDAP}.Ast.Extent.Text
    ${Function:GetDomainController}.Ast.Extent.Text
    ${Function:GetDomainName}.Ast.Extent.Text
    ${Function:GetElevation}.Ast.Extent.Text
    ${Function:GetGroupObjectsInLDAP}.Ast.Extent.Text
    ${Function:GetModuleDependencies}.Ast.Extent.Text
    ${Function:GetNativePath}.Ast.Extent.Text
    ${Function:GetUserObjectsInLDAP}.Ast.Extent.Text
    ${Function:GetWorkingCredentials}.Ast.Extent.Text
    ${Function:InstallFeatureDism}.Ast.Extent.Text
    ${Function:InvokeModuleDependencies}.Ast.Extent.Text
    ${Function:InvokePSCompatibility}.Ast.Extent.Text
    ${Function:ManualPSGalleryModuleInstall}.Ast.Extent.Text
    ${Function:NewUniqueString}.Ast.Extent.Text
    ${Function:RemoveSudoPwd}.Ast.Extent.Text
    ${Function:ResolveHost}.Ast.Extent.Text
    ${Function:TestIsValidIPAddress}.Ast.Extent.Text
    ${Function:TestLDAP}.Ast.Extent.Text
    ${Function:TestPort}.Ast.Extent.Text
    ${Function:TestSSH}.Ast.Extent.Text
    ${Function:UnzipFile}.Ast.Extent.Text
    ${Function:Configure-PwshRemotingCrossPlatform}.Ast.Extent.Text
    ${Function:Download-NuGetPackage}.Ast.Extent.Text
    ${Function:Get-CertificateOverview}.Ast.Extent.Text
    ${Function:Get-Certificates}.Ast.Extent.Text
    ${Function:Get-CimPnpEntity}.Ast.Extent.Text
    ${Function:Get-EnvironmentVariables}.Ast.Extent.Text
    ${Function:Get-EventLogSummary}.Ast.Extent.Text
    ${Function:Get-FirewallProfile}.Ast.Extent.Text
    ${Function:Get-FirewallRules}.Ast.Extent.Text
    ${Function:Get-IPRange}.Ast.Extent.Text
    ${Function:Get-LocalGroups}.Ast.Extent.Text
    ${Function:Get-LocalGroupUsers}.Ast.Extent.Text
    ${Function:Get-LocalUserBelongGroups}.Ast.Extent.Text
    ${Function:Get-LocalUsers}.Ast.Extent.Text
    ${Function:Get-Networks}.Ast.Extent.Text
    ${Function:Get-NetworkInfo}.Ast.Extent.Text
    ${Function:Get-PendingUpdates}.Ast.Extent.Text
    ${Function:Get-Processes}.Ast.Extent.Text
    ${Function:Get-PUDAdminCenter}.Ast.Extent.Text
    ${Function:Get-RegistrySubKeys}.Ast.Extent.Text
    ${Function:Get-RegistryValues}.Ast.Extent.Text
    ${Function:Get-RemoteDesktop}.Ast.Extent.Text
    ${Function:Get-ScheduledTasks}.Ast.Extent.Text
    ${Function:Get-ServerInventory}.Ast.Extent.Text
    ${Function:Get-SSHProbe}.Ast.Extent.Text
    ${Function:Get-StorageDisk}.Ast.Extent.Text
    ${Function:Get-StorageFileShare}.Ast.Extent.Text
    ${Function:Get-StorageVolume}.Ast.Extent.Text
    ${Function:Get-WUAHistory}.Ast.Extent.Text
    ${Function:Install-DotNet472}.Ast.Extent.Text
    ${Function:New-EnvironmentVariable}.Ast.Extent.Text
    ${Function:New-Runspace}.Ast.Extent.Text
    ${Function:Remove-EnvironmentVariable}.Ast.Extent.Text
    ${Function:Set-ComputerIdentification}.Ast.Extent.Text
    ${Function:Set-EnvironmentVariable}.Ast.Extent.Text
    ${Function:Set-RemoteDesktop}.Ast.Extent.Text
    ${Function:Start-DiskPerf}.Ast.Extent.Text
    ${Function:Stop-DiskPerf}.Ast.Extent.Text
    ${Function:Update-PowerShellCore}.Ast.Extent.Text
)

$RequiredLinuxCommands = @(
    "echo"
    "whoami"
    "domainname"
    "nslookup"
    "host"
    "hostname"
    "ldapsearch"
    "expect"
)

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU6z0WEiQy7/DYIymycSXmvvYz
# pSqgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFCxsbIJdtXfKk0je
# nxIv6ke63erZMA0GCSqGSIb3DQEBAQUABIIBAIOhn1fGJQnYNKhRjKe2EDZLoDf6
# RfCtbsGeUZQjMl9X3T9rBI8fkqSRtYCoZMtk+Wp2RtYxLZOhVNxYJs2LwHvBDIsq
# 3VdvYhuNoWQcagNV1f+H2nuazQsFfKkSgjPEsKt/pRQXOu9wBKfjNhe0eb81ontc
# 2iM2PBKTBqFV6C6kdCa4GMLAHks1AFGr8yBmmKWTNlkhoWqUAQRhEkSPEpQCu+qi
# aFyYI08hH6fK0k+9BI2aHMG5gjF+ua5NlTR+RjPnbEqnSkbkBxpE3t6xU1922aDm
# eVfXFAfK62/uNj1ldkKA2ib0AMawiqXkjqDKAAhiYvwaBgq4tgAKc3KTK7w=
# SIG # End signature block
