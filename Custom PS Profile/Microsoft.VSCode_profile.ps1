Set-Location C:\
Clear-Host
Write-Host "Beast mode active. Go get 'em, tiger."
function Get-Time { return $(get-date | ForEach-Object { $_.ToLongTimeString() } ) }
function prompt {
    # Write the time
    write-host "[" -noNewLine
    write-host $(Get-Time) -foreground yellow -noNewLine
    write-host "] " -noNewLine
    # Write the path
    write-host $($(Get-Location).Path.replace($home, "~").replace("\", "/")) -foreground green -noNewLine
    write-host $(if ($nestedpromptlevel -ge 1) { '>>' }) -noNewLine
    return "> "
}