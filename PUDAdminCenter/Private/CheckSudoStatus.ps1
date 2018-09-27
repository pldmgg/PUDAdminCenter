function CheckSudoStatus {
    [CmdletBidning()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$UserNameShort,

        [Parameter(Mandatory=$False)]
        [string]$DomainNameShort,

        [Parameter(Mandatory=$False)]
        [string]$RemoteHostName
    )

    $BashScript = @'
prompt=$(sudo -n pwsh -c \"'test'\" 2>&1)
if [ $? -eq 0 ]; then
  # exit code of sudo-command is 0
  echo "NoPasswordPrompt"
elif echo $prompt | grep -q '^sudo:'; then
  echo "PasswordPrompt"
else
  echo "NoSudoPrivileges"
fi
'@

    $SSHOutput = ssh $UserNameShort@$DomainNameShort@$RemoteHostName -t "$BashScript"

    $SSHOutput.Trim()
}

