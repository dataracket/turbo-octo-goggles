if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco feature enable -n allowGlobalConfirmation
choco install googlechrome
choco install filezilla -v
choco install lightshot -v
choco install rufus -v
choco install 7zip.install -v
choco install notepadplusplus.install -v
choco install git.install -v
choco install putty.install -v
choco install skype -v
choco install procexp -v
choco install malwarebytes -v
choco install teamviewer
choco install chocolateygui
choco install github -v
choco install vscode -v
choco install vscode-icons -v
choco install rsat -v
choco install windirstat -v
choco install slack -v
choco install lastpass -v
choco install everything -v
choco install speccy -v
choco install mremoteng -v
choco install todoist -v
choco install toggl -v
choco install keypirinha -v
choco install whatsapp -v
choco install discord -v
choco install

