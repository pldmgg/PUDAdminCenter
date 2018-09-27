function RemoveSudoPwd {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$UserNameShort,

        [Parameter(Mandatory=$False)]
        [string]$DomainNameShort,

        [Parameter(Mandatory=$False)]
        [string]$RemoteHostName,

        [Parameter(Mandatory=$False)]
        [string]$SudoPwd
    )

    $AppendSudoersScript = @"
echo 'Cmnd_Alias SUDO_PWSH = /bin/pwsh' | sudo EDITOR='tee -a' visudo
echo 'Defaults!SUDO_PWSH !requiretty' | sudo EDITOR='tee -a' visudo
echo '%$DomainNameShort\\$UserNameShort ALL=(ALL) NOPASSWD: SUDO_PWSH' | sudo EDITOR='tee -a' visudo
"@
    $BashScriptPreamble = @"
export HISTCONTROL=ignorespace; echo $SudoPwd | sudo $AppendSudoersScript
"@
    
    ssh $UserNameShort@$DomainNameShort@$RemoteHostName -t "$BashScriptPreamble" *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "There was an issue executing the remote ssh command on '$UserNameShort@$DomainNameShort@$RemoteHostName'! Halting!"
        $global:FunctionResult = "1"
        return
    }
}