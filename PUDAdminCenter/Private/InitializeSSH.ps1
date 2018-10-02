function InitializeSSH {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [ValidateSet("Windows","Linux")]
        [string]$RemoteOSGuess = "Windows",

        [Parameter(Mandatory=$True)]
        [string]$RemoteHostNameOrIP,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("\\")] # Must be in format <RemoteHostName>\<User>
        [string]$LocalUserName,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("\\")] # Must be in format <DomainShortName>\<User>
        [string]$DomainUserName,

        [Parameter(Mandatory=$False)]
        [string]$LocalPassword,

        [Parameter(Mandatory=$False)]
        [string]$DomainPassword,

        [Parameter(Mandatory=$False)]
        [string]$KeyFilePath,

        [Parameter(Mandatory=$False)]
        $OutputTracker
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
            ![bool]$($($CheckForExpectedResponses -split "`n") -match "^}") -and $Counter -le 10
            ) {
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                if ($CheckResponsesOutput -match "must be greater than zero" -or $CheckResponsesOutput[-1] -notmatch "[a-zA-Z]") {
                    break
                }
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 11) {
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
                            Stop-Process -Id $PSAwaitProcess.Id
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
                            Stop-Process -Id $PSAwaitProcess.Id
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
                $SuccessOrAcceptHostKeyOrPwdPrompt -notmatch "^}" -and $Counter -le 10
                ) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 11) {
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
                                Stop-Process -Id $PSAwaitProcess.Id
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
                            Stop-Process -Id $PSAwaitProcess.Id
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
                ![bool]$($($CheckExpectedSendYesOutput -split "`n") -match "^}") -and $Counter -le 10
                ) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 11) {
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
                                Stop-Process -Id $PSAwaitProcess.Id
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
                    while (![bool]$($($JsonOutputPrep -split "`n") -match "^}") -and $Counter -le 10) {
                        $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                        if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                            $null = $JsonOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                        }
                        Start-Sleep -Seconds 1
                        $Counter++
                    }
                    if ($Counter -eq 11) {
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
                                    Stop-Process -Id $PSAwaitProcess.Id
                                    while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                        Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                        Start-Sleep -Seconds 1
                                    }
                                }
                            }
                        }

                        return
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
                while (![bool]$($($JsonOutputPrep -split "`n") -match "^}") -and $Counter -le 10) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                        $null = $JsonOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    }
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 11) {
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
                                Stop-Process -Id $PSAwaitProcess.Id
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                }
                            }
                        }
                    }

                    return
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
                        Stop-Process -Id $PSAwaitProcess.Id
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
            
            # NOTE: The below $ShellDetermination refers to the shell you will (probably) end up in if you use an ssh command, NOT PSRemoting
            if ($SSHCheckAsJson.Output -eq "ConnectionSuccessful") {
                if ($SSHCheckAsJson.Platform -eq "Win32NT") {
                    $OSDetermination = "Windows"
                    $ShellDetermination = "pwsh"
                    $OSVersionInfo = $SSHCheckAsJson.DistroInfo
                }
                else {
                    $OSDetermination = "Linux"
                    $ShellDetermination = "pwsh"
                    $OSVersionInfo = $SSHCheckAsJson.DistroInfo
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
            $null = $SSHCmdStringArray.Add("-t")
            if ($LocalUserName -and $LocalPassword) {
                $null = $SSHCmdStringArray.Add("$FullUserName@$RHostIP")
            }
            if ($DomainUserName -and $DomainPassword) {
                $null = $SSHCmdStringArray.Add("$FullUserName@$DomainNameShort@$RHostIP")
            }
            $Bytes = [System.Text.Encoding]::Unicode.GetBytes('$PSVersionTable | ConvertTo-Json')
            $EncodedCommandPSVerTable = [Convert]::ToBase64String($Bytes)
            $Bytes = [System.Text.Encoding]::Unicode.GetBytes('"Cim OS Info: " + $(Get-CimInstance Win32_OperatingSystem).Caption')
            $EncodedCommandWinOSCim = [Convert]::ToBase64String($Bytes)
            $SSHScript = @(
                "echo 111ConnectionTest111"
                "echo ConnectionSuccessful"
                "echo 111RootDirInfo111"
                "dir /"
                "echo 111ProcessInfo111"
                "Get-Process -Id `$PID"
                "echo 111PwshJson111"
                "pwsh -NoProfile -EncodedCommand '$EncodedCommandPSVerTable'"
                "echo 111PowerShellCimInfo111"
                "powershell -NoProfile -EncodedCommand '$EncodedCommandWinOSCim'"
                "echo 111UnameOutput111"
                "uname -a"
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
            ![bool]$($($CheckForExpectedResponses -split "`n") -match "^}") -and $Counter -le 10
            ) {
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                if ($CheckResponsesOutput -match "must be greater than zero" -or $CheckResponsesOutput[-1] -notmatch "[a-zA-Z]") {
                    break
                }
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 11) {
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
                            Stop-Process -Id $PSAwaitProcess.Id
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
                            Stop-Process -Id $PSAwaitProcess.Id
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
                $SuccessOrAcceptHostKeyOrPwdPrompt -notmatch "^}" -and $Counter -le 10
                ) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 11) {
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
                                Stop-Process -Id $PSAwaitProcess.Id
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
                            Stop-Process -Id $PSAwaitProcess.Id
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
                ![bool]$($($CheckExpectedSendYesOutput -split "`n") -match "^}") -and $Counter -le 10
                ) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 11) {
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
                                Stop-Process -Id $PSAwaitProcess.Id
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
                    while (![bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful") -and $Counter -le 10) {
                        $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                        if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                            $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                        }
                        Start-Sleep -Seconds 1
                        $Counter++
                    }
                    if ($Counter -eq 11) {
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
                                    Stop-Process -Id $PSAwaitProcess.Id
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
                while (![bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful") -and $Counter -le 10) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                        $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    }
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 11) {
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
                                Stop-Process -Id $PSAwaitProcess.Id
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
                        Stop-Process -Id $PSAwaitProcess.Id
                        while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                            Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                            Start-Sleep -Seconds 1
                        }
                    }
                }
            }

            if ([bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful")) {
                if ($SSHOutputPrep -match "^ConnectionSuccessful; echo 111RootDirInfo111;") {
                    $OSDetermination = "Windows"
                    $ShellDetermination = "cmd"
                    $OSVersionInfo = $null
                }
                elseif ($SSHOutputPrep -match "111RootDirInfo111.*Directory:.*[a-zA-Z]:\\") {
                    $OSDetermination = "Windows"
                    if ($SSHOutputPrep -match "111ProcessInfo111.*Name[\s]+:[\s]+powershell") {
                        $ShellDetermination = "powershell"
                        # The below $OSVersionInfo will be a string that looks something like:
                        #   Microsoft Windows Server 2016 Standard Evaluation
                        $OSVersionInfo = $($($($SSHOutputPrep -split "`n") -match "Cim OS Info:") -replace "Cim OS Info: ","").Trim()
                    }
                    elseif ("111ProcessInfo111.*Name[\s]+:[\s]+pwsh") {
                        $ShellDetermination = "pwsh"
                        # The below $OSVersionInfo will be a string that looks something like:
                        #   Microsoft Windows Server 2016 Standard Evaluation
                        $OSVersionInfo = $($($($SSHOutputPrep -split "`n") -match "Cim OS Info:") -replace "Cim OS Info: ","").Trim()
                    }
                }
                elseif ($SSHOutputPrep -match "111RootDirInfo111.*etc " -and !$($SSHOutputPrep -match "111RootDirInfo111.*Directory:.*[a-zA-Z]:\\")) {
                    $OSDetermination = "Linux"
                    if ($SSHOutputPrep -match "111ProcessInfo111.*Name[\s]+:[\s]+pwsh") {
                        $ShellDetermination = "pwsh"
                    }
                    else {
                        $ShellDetermination = "bash"
                    }

                    $UnameOutputHeaderIndex = $($SSHOutputPrep -split "`n").IndexOf("111UnameOutput111")
                    $OSVersionInfo = $($SSHOutputPrep -split "`n")[$($UnameOutputHeaderIndex + 1)]
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
                '    Platform = $PSVersionTable.Platform'
                '    DistroInfo = $PSVersionTable.OS'
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

            $JsonStartIndex = $ExpectOutput.IndexOf($($ExpectOutput -match '"Output"'))
            $JsonEndIndex = $ExpectOutput.IndexOf($($ExpectOutput -match '^}$'))
            [System.Collections.ArrayList]$FinalJson = $ExpectOutput[$JsonStartIndex..$JsonEndIndex]
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
                    $OSVersionInfo = $SSHCheckAsJson.DistroInfo
                }
                else {
                    $OSDetermination = "Linux"
                    $ShellDetermination = "pwsh"
                    $OSVersionInfo = $SSHCheckAsJson.DistroInfo
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
            $null = $SSHCmdStringArray.Add("-t")
            if ($LocalUserName -and $LocalPassword) {
                $null = $SSHCmdStringArray.Add("$FullUserName@$RHostIP")
            }
            if ($DomainUserName -and $DomainPassword) {
                $null = $SSHCmdStringArray.Add("$FullUserName@$DomainNameShort@$RHostIP")
            }
            $Bytes = [System.Text.Encoding]::Unicode.GetBytes('$PSVersionTable | ConvertTo-Json')
            $EncodedCommandPSVerTable = [Convert]::ToBase64String($Bytes)
            $Bytes = [System.Text.Encoding]::Unicode.GetBytes('"Cim OS Info: " + $(Get-CimInstance Win32_OperatingSystem).Caption')
            $EncodedCommandWinOSCim = [Convert]::ToBase64String($Bytes)
            $SSHScript = @(
                "echo 111ConnectionTest111"
                "echo ConnectionSuccessful"
                "echo 111RootDirInfo111"
                "dir /"
                "echo 111ProcessInfo111"
                "Get-Process -Id `$PID"
                "echo 111PwshJson111"
                "pwsh -NoProfile -EncodedCommand '$EncodedCommandPSVerTable'"
                "echo 111PowerShellCimInfo111"
                "powershell -NoProfile -EncodedCommand '$EncodedCommandWinOSCim'"
                "echo 111UnameOutput111"
                "uname -a"
            )
            $SSHScript = $SSHScript -join "; "
            $null = $SSHCmdStringArray.Add($('"' + $SSHScript + '"'))
            # NOTE: The below -replace regex string removes garbage escape sequences like: [116;1H
            $SSHCmdString = $script:SSHCmdString = '@($(' + $($SSHCmdStringArray -join " ") + ') -replace "\e\[(\d+;)*(\d+)?[ABCDHJKfmsu]","") 2>$null'

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
                '        expect eof'
                '    }'
                '}'
                'EOF'
            )
            $ExpectScript = $ExpectScriptPrep -join "`n"
            
            # The below $ExpectOutput is an array of strings
            $ExpectOutput = bash -c "$ExpectScript"

            $SSHOutputPrep = $ExpectOutput

            if ([bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful")) {
                if ($SSHOutputPrep -match "^ConnectionSuccessful; echo 111RootDirInfo111;") {
                    $OSDetermination = "Windows"
                    $ShellDetermination = "cmd"
                    $OSVersionInfo = $null
                }
                elseif ($SSHOutputPrep -match "111RootDirInfo111.*Directory:.*[a-zA-Z]:\\") {
                    $OSDetermination = "Windows"
                    if ($SSHOutputPrep -match "111ProcessInfo111.*Name[\s]+:[\s]+powershell") {
                        $ShellDetermination = "powershell"
                        # The below $OSVersionInfo will be a string that looks something like:
                        #   Microsoft Windows Server 2016 Standard Evaluation
                        $OSVersionInfo = $($($($SSHOutputPrep -split "`n") -match "Cim OS Info:") -replace "Cim OS Info: ","").Trim()
                    }
                    elseif ("111ProcessInfo111.*Name[\s]+:[\s]+pwsh") {
                        $ShellDetermination = "pwsh"
                        # The below $OSVersionInfo will be a string that looks something like:
                        #   Microsoft Windows Server 2016 Standard Evaluation
                        $OSVersionInfo = $($($($SSHOutputPrep -split "`n") -match "Cim OS Info:") -replace "Cim OS Info: ","").Trim()
                    }
                }
                elseif ($SSHOutputPrep -match "111RootDirInfo111.*etc " -and !$($SSHOutputPrep -match "111RootDirInfo111.*Directory:.*[a-zA-Z]:\\")) {
                    $OSDetermination = "Linux"
                    if ($SSHOutputPrep -match "111ProcessInfo111.*Name[\s]+:[\s]+pwsh") {
                        $ShellDetermination = "pwsh"
                    }
                    else {
                        $ShellDetermination = "bash"
                    }

                    $UnameOutputHeaderIndex = $($SSHOutputPrep -split "`n").IndexOf("111UnameOutput111")
                    $OSVersionInfo = $($SSHOutputPrep -split "`n")[$($UnameOutputHeaderIndex + 1)]
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
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUhEnXL4pe9hhpSfvnGQTRKsc2
# g5egggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFOfJanMfwKsD77Rs
# 1wtAgtuejNNPMA0GCSqGSIb3DQEBAQUABIIBAIk+RJ4S4Z7yauDuRe7TEIoHipOP
# qITfusL1ZnEx/alCJZbIxuefKUKXJdGKQ4V6Hhe+b5NiJSWsEtYmR68ORXkTX8pT
# 34ZGQDu8oo1eStlsflauouDvA7o58GLUKCkeIQ2EK5vpgxM+Mfu3Q0iTnLIRs+nn
# gCb/IYfzyKATeIQ4ya9J5qvySReBIx8wiwTUV1ApiiH+tbggP1RSfNEVxzV2+FJu
# 7HYNrvLu+KtXMq1m2YuTUbhyPlXRDC5EeRhbLVtJ7BKGs/hASAuF4XuPzm4xs+QZ
# kwcNsob7BeKQ65WhZWbDFAHvV6fOqMNwbOTUHULHvbPIK3MPTO85O3C+Lzo=
# SIG # End signature block
