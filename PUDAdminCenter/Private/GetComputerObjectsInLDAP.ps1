function GetComputerObjectsInLDAP {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [int]$ObjectCount = 0,

        [Parameter(Mandatory=$False)]
        [string]$Domain,

        [Parameter(Mandatory=$False)]
        [pscredential]$LDAPCreds
    )

    if ($PSVersionTable.Platform -eq "Unix" -and !$LDAPCreds) {
        Write-Error "On this Platform (i.e. $($PSVersionTable.Platform)), you must provide credentials with access to LDAP/Active Directory using the -LDAPCreds parameter! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Make sure the $LDAPCreds.UserName is in the correct format
    if ($LDAPCreds.UserName -notmatch "\\") {
        Write-Error "The -LDAPCreds UserName is NOT in the correct format! The format must be: <Domain>\<User>"
        $global:FunctionResult = "1"
        return
    }

     # Determine if we have the required Linux commands
     [System.Collections.ArrayList]$LinuxCommands = @(
        "host"
        "hostname"
        "ldapsearch"
    )
    if (!$Domain) {
        $null = $LinuxCommands.Add("domainname")
    }
    [System.Collections.ArrayList]$CommandsNotPresent = @()
    foreach ($CommandName in $LinuxCommands) {
        $CommandCheckResult = command -v $CommandName
        if (!$CommandCheckResult) {
            $null = $CommandsNotPresent.Add($CommandName)
        }
    }

    if ($CommandsNotPresent.Count -eq 1 -and $CommandsNotPresent -contains "ldapsearch") {
        $PackageManagerList = @('pacman','dnf','yum','apt','zypper')
        
        if ($(command -v pacman)) {
            $null = pacman -S openldap-clients --noconfirm
        }

        if ($(command -v yum)) {
            $null = yum -y install openldap-clients
        }
        elseif ($(command -v dnf)) {
            $null = dnf -y install openldap-clients
        }

        if ($(command -v apt)) {
            $null = apt -y install openldap-clients
        }

        if ($(command -v zypper)) {
            $null = zypper install openldap-clients --non-interactive
        }

        $ldapsearchCheckResult = command -v 'ldapsearch'
        if (!$ldapsearchCheckResult) {
            Write-Error "Unable to find the 'ldapsearch' command post-install! Halting!"
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
        Write-Error "The following Linux commands are required, but not present on $(hostname):`n$($CommandsNotPresent -join "`n")`nHalting!"
        $global:FunctionResult = "1"
        return
    }

    # Below $LDAPInfo Output is PSCustomObject with properties: DirectoryEntryInfo, LDAPBaseUri,
    # GlobalCatalogConfigured3268, GlobalCatalogConfiguredForSSL3269, Configured389, ConfiguredForSSL636,
    # PortsThatWork
    try {
        if ($Domain) {
            $DomainControllerInfo = GetDomainController -Domain $Domain -ErrorAction Stop
        }
        else {
            $DomainControllerInfo = GetDomainController -ErrorAction Stop
        }

        if ($DomainControllerInfo.PrimaryDomainController -eq "unknown") {
            $PDC = $DomainControllerInfo.FoundDomainControllers[0]
        }
        else {
            $PDC = $DomainControllerInfo.PrimaryDomainController
        }

        $LDAPInfo = TestLDAP -ADServerHostNameOrIP $PDC -ErrorAction Stop
        if (!$DomainControllerInfo) {throw "Problem with GetDomainController function! Halting!"}
        if (!$LDAPInfo) {throw "Problem with TestLDAP function! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if (!$LDAPInfo.PortsThatWork) {
        Write-Error "Unable to access LDAP on $PDC! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($LDAPInfo.PortsThatWork -contains "389") {
        $Port = "389"
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":$Port"
    }
    elseif ($LDAPInfo.PortsThatWork -contains "3268") {
        $Port = "3268"
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":$Port"
    }
    elseif ($LDAPInfo.PortsThatWork -contains "636") {
        $Port = "636"
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":$Port"
    }
    elseif ($LDAPInfo.PortsThatWork -contains "3269") {
        $Port = "3269"
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":$Port"
    }

    if ($PSVersionTable.Platform -eq "Unix") {
        $SimpleDomainPrep = $PDC -split "\."
        $SimpleDomain = $SimpleDomainPrep[1..$($SimpleDomainPrep.Count-1)] -join "."
        [System.Collections.ArrayList]$DomainLDAPContainersPrep = @()
        foreach ($Section in $($SimpleDomain -split "\.")) {
            $null = $DomainLDAPContainersPrep.Add($Section)
        }
        $DomainLDAPContainers = $($DomainLDAPContainersPrep | foreach {"DC=$_"}) -join ","
        $BindUserName = $LDAPCreds.UserName
        $BindPassword = $LDAPCreds.GetNetworkCredential().Password

        $ldapSearchOutput = ldapsearch -x -h $PDC -D $BindUserName -w $BindPassword -b $DomainLDAPContainers -s sub "(objectClass=computer)" cn
        if ($LASTEXITCODE -ne 0) {
            if ($LASTEXITCODE -eq 49) {
                Write-Error "Invalid credentials. Please check them and try again. Halting!"
                $global:FunctionResult = "1"
                return
            }
            else {
                Write-Error "Unable to read LDAP! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        $ComputerObjectsInLDAP = $($ldapSearchOutput -split "`n") -match "cn: "
        if ($ObjectCount -gt 0) {
            $ComputerObjectsInLDAP = $ComputerObjectsInLDAP[0..$($ObjectCount-1)]
        }
    }
    else {
        <#
        $LDAPSearchRoot = [System.DirectoryServices.DirectoryEntry]::new($LDAPUri)
        $LDAPSearcher = [System.DirectoryServices.DirectorySearcher]::new($LDAPSearchRoot)
        $LDAPSearcher.Filter = "(&(objectCategory=Group))"
        $LDAPSearcher.SizeLimit = 0
        $LDAPSearcher.PageSize = 250
        $GroupObjectsInLDAP = $LDAPSearcher.FindAll() | foreach {$_.GetDirectoryEntry()}
        #>

        $LDAPSearchRoot = [System.DirectoryServices.DirectoryEntry]::new($LDAPUri)
        $LDAPSearcher = [System.DirectoryServices.DirectorySearcher]::new($LDAPSearchRoot)
        $LDAPSearcher.Filter = "(objectClass=computer)"
        $LDAPSearcher.SizeLimit = $ObjectCount
        $LDAPSearcher.PageSize = 250
        $ComputerObjectsInLDAP = $LDAPSearcher.FindAll() | foreach {$_.GetDirectoryEntry()}
        <#
        $null = $LDAPSearcher.PropertiesToLoad.Add("name")
        [System.Collections.ArrayList]$ServerList = $($LDAPSearcher.FindAll().Properties.GetEnumerator()).name
        $null = $ServerList.Insert(0,"Please Select a Server")
        #>
    }

    $ComputerObjectsInLDAP
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUkgXSJt1SdBFOvByBh63DzPZ1
# k0qgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFGSePC6IKfa3s2QT
# tACIqvZDvZ13MA0GCSqGSIb3DQEBAQUABIIBACiBv3hDljONjOYMaAZx4dd8ePYl
# bU40AHYpASniZMA+ub3jLnLQYnq+XlDw8TpglFWKVxaa1lEJq41XiiW6nLsLYpSX
# oQ3Ely6DDj19MnLAqTSGplQtVl9cyNexNTft4E/t+Wtm7CoEpOV1YW693TmWErO5
# JH3syVIuX49FLswCfU4FrT+uqXvmSwS7Mfo53UHfA28Oc4Z+KxvNHFu7qMmIB2rP
# A7nbHFnMsMU1VfLliVL1JbvCuuiX3Ntv6x4RB1eOT4iKyKkLKIP2SnXNTS8DjeWZ
# bMA138W0bRpIYOrw23o9Efmt+iyz0JDqF1pXaiWy1nH3ztO+Wg8my2g8Zwo=
# SIG # End signature block
