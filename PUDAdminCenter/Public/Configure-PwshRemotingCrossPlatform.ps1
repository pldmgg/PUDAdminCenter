function Configure-PwshRemotingViaSSH {
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
        [string]$SSHCmdOptions # Should be in format: ssh -o <option(s)> -i <keyfilepath> -t <user>@<remotehost>
    )

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

        }
        if ($Shell -eq "powershell") {
            $InstallPwshScriptPrep = @(
                'if ($(Get-Module -ListAvailable).Name -notcontains "WinSSH") {$null = Install-Module WinSSH -ErrorAction Stop}'
                'if ($(Get-Module).Name -notcontains "WinSSH") {$null = Import-Module WinSSH -ErrorAction Stop}'
                'Install-WinSSH -GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell pwsh'
            )
            $InstallPwshScript = $InstallPwshScriptPrep -join "`n"

            $FinalSSHCmdString = $SSHCmdOptions + ' ' + '"' + $InstallPwshScript + '"'
            $InstallPwshResult = [scriptblock]::Create($FinalSSHCmdString).InvokeReturnAsIs()
        }
        if ($Shell -eq "pwsh") {
            $InstallPwshScriptPrep = @(
                'if ($(Get-Module -ListAvailable).Name -notcontains "WinSSH") {$null = Install-Module WinSSH -ErrorAction Stop}'
                'if ($(Get-Module).Name -notcontains "WinSSH") {$null = Import-Module WinSSH -ErrorAction Stop}'
                'Install-WinSSH -GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell pwsh'
            )
            $InstallPwshScript = $InstallPwshScriptPrep -join "`n"

            $FinalSSHCmdString = $SSHCmdOptions + ' ' + '"' + $InstallPwshScript + '"'
            $InstallPwshResult = [scriptblock]::Create($FinalSSHCmdString).InvokeReturnAsIs()
        }
    }

    $InstallPwshResult
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU+ccjSbaHuIwbvb9d0zF5KcMX
# dmOgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFMTVAMtn455nteF5
# VSxFGEkv12wLMA0GCSqGSIb3DQEBAQUABIIBAHc66LKNHljGgNOpYW7ohisbhYXg
# dxjF4N2qqsoqO9z1OZKB0y3MbQD3YBTeTJ9lpSRyCzjpMSFWkHqqwxmLjlDSX9Cf
# m1/0E+/WJBufY1iZbzI/Ilz9q9BjUOccAxKohN72ExyE4BuG5MVWZdS+8/w+w8QQ
# Yib03PqC0XFkxSVLkYpERLP/MlmANYQszjzZca181Y9z+OdOPKjwCdL8aZfLpS1i
# sLAxl3ZCOLB/bng4RIz50Pnlkqx+WBhCfVPlor1qiXP4t7W7K5ZUFKGvsL1QorFA
# y8cO7FTGDrg3JQQzr8qRJYVarp9MkfY/ML/85gNEqQA+1St1mk3PW5lGIFw=
# SIG # End signature block
