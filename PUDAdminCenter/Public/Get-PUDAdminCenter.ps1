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
        [switch]$RemoveExistingPUD = $True
    )

    #region >> Prep

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

    # Make sure we can resolve the $DomainName
    try {
        $DomainName = $(Get-CimInstance Win32_ComputerSystem).Domain
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
    [System.Collections.ArrayList]$InitialRemoteHostListPrep = $(GetComputerObjectsInLDAP -ObjectCount 20).Name
    # Let's just get 20 of them initially. We want *something* on the HomePage but we don't want hundreds/thousands of entries. We want
    # the user to specify individual/range of hosts/devices that they want to manage.
    #$InitialRemoteHostListPrep = $InitialRemoteHostListPrep[0..20]
    if ($PSVersionTable.PSEdition -eq "Core") {
        [System.Collections.ArrayList]$InitialRemoteHostListPrep = $InitialRemoteHostListPrep | foreach {$_ -replace "CN=",""}
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
    
                    [System.Collections.ArrayList]$PSRemotingMethodValues = @("WinRM")
                    if ($PUDRSSyncHT."$Session:ThisRemoteHost`Info".RHostTableData.SSH -eq "Available") {
                        $null = $PSRemotingMethodValues.Add("SSH")
                    }
                    New-UDInputField -Type select -Name 'Preferred_PSRemotingMethod' -Values @("WinRM","SSH") -DefaultValue "WinRM"
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
                        if ($Domain_UserName -and $DOmain_Password) {
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
                        New-UDInputAction -Toast "SSH was SUCCESSFUL, however, ssh functionality has not been fully implemented yet. Please use WinRM instead." -Duration 10000
                        Sync-UDElement -Id "CredsForm"
                        return
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
    
                    [System.Collections.ArrayList]$ScanRemoteHostListPrep = $(GetComputerObjectsInLDAP -ObjectCount 100).Name
                    # Let's just get 20 of them initially. We want *something* on the HomePage but we don't want hundreds/thousands of entries. We want
                    # the user to specify individual/range of hosts/devices that they want to manage.
                    #$ScanRemoteHostListPrep = $ScanRemoteHostListPrep[0..20]
                    if ($PSVersionTable.PSEdition -eq "Core") {
                        [System.Collections.ArrayList]$ScanRemoteHostListPrep = $ScanRemoteHostListPrep | foreach {$_ -replace "CN=",""}
                    }
    
                    # Filter Out the Remote Hosts that we can't resolve
                    [System.Collections.ArrayList]$ScanRemoteHostList = @()
    
                    $null = Clear-DnsClientCache
                    foreach ($HName in $ScanRemoteHostListPrep) {
                        try {
                            $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $HName -ErrorAction Stop
    
                            if ($ScanRemoteHostList.FQDN -notcontains $RemoteHostNetworkInfo.FQDN) {
                                $null = $ScanRemoteHostList.Add($RemoteHostNetworkInfo)
                            }
                        }
                        catch {
                            continue
                        }
                    }
    
                    $PUDRSSyncHT.RemoteHostList = $ScanRemoteHostList
    
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
    
                            $HostNames = $HostNameTextBox.Attributes['value']
                            $IPAddresses = $IPTextBox.Attributes['value']
    
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
    
                                    $null = $RemoteHostList.Add($RemoteHostNetworkInfo)
                                }
                                catch {
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

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU0w4+0zAltB2uO2XLPiuDjoub
# w+Cgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFG96MsHo/PnwrggG
# ZLXy488uL/byMA0GCSqGSIb3DQEBAQUABIIBAJc+Z2liE0a7J5rjMamBqB8kEcvT
# UG9uVeHu6RtVAQ76zi04CQrBXwMdf/VQb4n/D/L0O6065E8WIGChxQ/8mZlUEMmK
# GboQc5kAwe1mMqKntYN0fQ5lQZypQxiMIrmbA4wzBVSqS/4sckibHzieQKl3hztB
# rgLOUTcxxhIyAQ+Nkmg6PGOvD5Q1XWblXTehPy0834rDiGZreWCtKitMVfmaWoUW
# 4/1cQVpQn3rrDkeGWfpMCSfCIYqC5t+7TwLMYG76A6POzH2kceovpb9ssf0WjPz7
# XJrzg/UJixyRDdfNekQ3RrWfuYn4FNEqhMxJBfLpssALb6RCFsUsAnevl3Y=
# SIG # End signature block
