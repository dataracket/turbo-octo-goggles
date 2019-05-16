$ProVersion = "v0.0.2"
$ProName = "| TekPS $ProVersion |"
<#
Author: Alex Gust aka TekGoose

Update Notes:
Version 0.0.2
    - Updated script to pull from Github repo
Version 0.0.1:
    - Cleaned entire script
    - Added versioning
    - Hello World!
#>

#TekGoose Customizations:
Set-Location C:\
$host.UI.RawUI.WindowTitle = Get-Location
$Host.UI.RawUI.ForegroundColor = "white"
$Host.UI.RawUI.BackgroundColor = "black"

function Menu {

    Write-Host(" ----------------------- ")
    Write-Host("$ProName")
    Write-Host(" ----------------------- ")
#    Write-Host('Type "GUI" to launch GUI interface!')
    Write-Host("")
    Write-Host("Command             Function")
    Write-Host("-------             --------")
    Write-Host("choco               Activates Choco")
    Write-Host -ForegroundColor Red ("cl                  Clear Shell and Reprint Command Menu")
    Write-Host -ForegroundColor Red ("CLACMenu            Retrieve CLAC custom cmdlets. Alias:  clac")
    Write-Host("HuntUser            Query SCCM For Last System Logged On By Specified User")
    Write-Host("LastBoot            Get Last Reboot Time")
    Write-Host("RDP                 Remote Desktop")
    Write-Host("RmUserProf          Clear User Profiles")
    Write-Host("Update-Profile       Update PowerShell Profile (Will Overwrite Current Version & Any Changes)")
    Write-Host("sf                  Activates Screenfetch")
    Write-Host("")
}#End PrintMenu
function Get-Time {
<#
.SYNOPSIS
    Used to get the current time and export it to the prompt.

.DESCRIPTION
    N/A

.EXAMPLE
    Get-Time
#>
    return $(get-date | ForEach-Object { $_.ToLongTimeString() } )
}
function prompt {
<#
.SYNOPSIS
    Used to change the prompt in PS to add a timestamp and customize color

.DESCRIPTION
    At the beginning of every prompt, adds the current time as a string. Customizes color of Get-Location

.EXAMPLE
    prompt
#>
    # Write the time
    write-host "[" -noNewLine
    write-host $(Get-Time) -foreground yellow -noNewLine
    write-host "] " -noNewLine
    # Write the path
    write-host $($(Get-Location).Path.replace($home, "~").replace("\", "/")) -foreground green -noNewLine
    write-host $(if ($nestedpromptlevel -ge 1) { '>>' }) -noNewLine
    return "> "
}
function exp {
    Invoke-Item .
}
function cl {
    <#
.SYNOPSIS
    Used to clear current PowerShell window

.DESCRIPTION
    Clears screen (same as clear) but, writes created 'PrintMenu' back onto the main shell for function reference

.EXAMPLE
    cl
#>

    #Clear Shell Prompt
    Clear-Host
    Write-Host -ForegroundColor Green "Beast mode active. Go get 'em, tiger."
}#End cl

function off {
powershell (Add-Type '[DllImport(\"user32.dll\")]^public static extern int SendMessage(int hWnd, int hMsg, int wParam, int lParam);' -Name a -Pas)::SendMessage(-1,0x0112,0xF170,2)
}

function HuntUser {
<#
.SYNOPSIS
    Retrieve workstation(s) last logged on by user (SAM Account Name)

.DESCRIPTION
    The HuntUser function will retrieve workstation(s) by the last logged on user (SAM Account Name). This queries SCCM; accuracy will depend on the last time each workstation has communicated with SCCM.

.EXAMPLE
    HuntUser dewittj
#>

Param(

    [Parameter(Mandatory=$true)]
    [String[]]$SamAccountName,

    [Parameter(ValueFromPipeline=$true)]
    [String]$SiteName="ABC",

    [Parameter(ValueFromPipeline=$true)]
    [String]$SCCMServer="SERVER1234",

    [Parameter(ValueFromPipeline=$true)]
    [String]$SCCMNameSpace="root\sms\site_$SiteName",

    $i=0,
    $j=0
)

    function QuerySCCM {

        foreach ($User in $SamAccountName) {

            Write-Progress -Activity "Retrieving Last Logged On Computers By SAM Account Name..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $SAMAccountName.count) * 100) + "%") -CurrentOperation "Processing $($User)..." -PercentComplete ((($j++) / $SAMAccountName.count) * 100)

            $Computername = (Get-WmiObject -Namespace $SCCMNameSpace -Computername $SCCMServer -Query "select Name from sms_r_system where LastLogonUserName='$User'").Name

                foreach ($Computer in $Computername) {

                    [pscustomobject] @{

                        SAMAccountName = "$User"
                        LastComputer = "$Computer"
                }
            }
        }
    }

    QuerySCCM

}#End HuntUser

function Update-Profile {
<#
.SYNOPSIS
    Update PowerShell profile to current repository content.

.DESCRIPTION
    Update PowerShell profile to current repository content.

.EXAMPLE
    Update-Profile
#>
    Invoke-WebRequest -Uri "https://github.com/dataracket/turbo-octo-goggles/blob/master/Custom%20PS%20Profile/Microsoft.PowerShell_profile.ps1" -OutFile "C:\Temp\profile.ps1"
    $NetworkLocation = "C:\Temp\profile.ps1"
    $MyDocuments = [environment]::getfolderpath("mydocuments") + "\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
    $MyDocuments2 = [environment]::getfolderpath("mydocuments") + "\WindowsPowerShell\Profile.ps1"
    $MyDocuments3 = [environment]::GetFolderPath("mydocuments") + "\WindowsPowerShell\Microsoft.VSCode_profile.ps1"

    #Overwrite current $Profile for PowerShell and PowerShell ISE
    Copy-Item -path "$NetworkLocation" -destination "$MyDocuments" -Force
    Copy-Item -path "$NetworkLocation" -destination "$MyDocuments2" -Force
    Copy-Item -path "$NetworkLocation" -destination "$MyDocuments3" -Force

    #Reload PowerShell (commented out to see errors)
    #Powershell

}#End UpdateProfile

function RDP {
    <#
.SYNOPSIS
    Remote Desktop Protocol to specified workstation(s)

.EXAMPLE
    RDP Computer123456

.EXAMPLE
    RDP 123456
#>

    param(

        [Parameter(Mandatory = $true)]
        [String]$Computername
    )

    #Start Remote Desktop Protocol on specifed workstation
    & "C:\windows\system32\mstsc.exe" /v:$computername /fullscreen /credential /username agadmin
}#End RDP

function LastBoot {
    <#
.SYNOPSIS
    Retrieve last restart time for specified workstation(s)

.EXAMPLE
    LastBoot Computer123456

.EXAMPLE
    LastBoot 123456
#>

    param(

        [Parameter(Mandatory = $true)]
        [String[]]$ComputerName,

        $i = 0,
        $j = 0
    )

    foreach ($Computer in $ComputerName) {

        $computerOS = Get-WmiObject Win32_OperatingSystem -Computer $Computer

        [pscustomobject] @{

            ComputerName = $Computer
            LastReboot   = $computerOS.ConvertToDateTime($computerOS.LastBootUpTime)
        }
    }
}#End LastBoot

<#
	https://github.com/kjerk/shelljump

	Commands (aliased):
		jump (name)     | Jump to a previously bookmarked folder.
		jumps or marks  | List all existing bookmarks.
		mark (name)     | Bookmarks current directory as a given name.
		unmark (name)   | Removes named bookmark.

	Example:
		C:\> cd '.\Program Files\Sublime Text 2'
		C:\Program Files\Sublime Text 2> mark st2
		C:\Program Files\Sublime Text 2> cd \
		C:\> jump st2
		C:\Program Files\Sublime Text 2> marks
		st2        -> C:\Program Files\Sublime Text 2
        C:\Program Files\Sublime Text 2> unmark st2
#>

[System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions") | Out-Null

function New-Bookmark {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$newName
    )

    if ( Check-BookmarksTimestamp -eq $true ) {
        if (-not $global:bookmarks.ContainsKey($newName)) {
            if ($global:bookmarks.ContainsValue($PWD.ToString())) {
                "Warning: current path already bookmarked under different key."
            }

            $global:bookmarks.Add($newName, $PWD.ToString());

            Write-Bookmarks
        }
        else {
            "Key '$newName' already exists in bookmarks.";
        }
    }
    else {
        "Bookmarks on disk newer than loaded bookmarks. (Desynced)"
        "Please refresh them with Read-Bookmarks, or overwrite with Write-Bookmarks."
    }
}

function Remove-Bookmark {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$name
    )

    if ( Check-BookmarksTimestamp -eq $true ) {
        if ($global:bookmarks.ContainsKey($name)) {
            $global:bookmarks.Remove($name)  | Out-Null;
            Write-Bookmarks
        }
        else {
            "No key with value '$name' found."
        }
    }
    else {
        "Bookmarks on disk newer than loaded bookmarks. (Desynced)"
        "Please refresh them with Read-Bookmarks, or overwrite with Write-Bookmarks."
    }
}

function Read-Bookmarks {
    $fPath = "$([System.IO.Path]::GetDirectoryName($profile))\Jumps.json";

    if ([System.IO.File]::Exists($fPath)) {
        $Global:JumpFileTime = (Get-Item "$([System.IO.Path]::GetDirectoryName($profile))\Jumps.json").LastWriteTime;
        if (Test-Path $fPath) {
            $global:bookmarks = @{};
            $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
            $global:bookmarks = $ser.DeserializeObject((Get-Content $fPath))
        }
        else {
            $global:bookmarks = @{};
        }
    }
    else {
        $global:bookmarks = @{};
    }
}

function Check-BookmarksTimestamp {
    $bPath = "$([System.IO.Path]::GetDirectoryName($profile))\Jumps.json"

    if (Test-Path $bPath) {
        $fDate = (Get-Item "$([System.IO.Path]::GetDirectoryName($profile))\Jumps.json").LastWriteTime;

        if ($fDate -gt $Global:JumpFileTime) {
            return $false;
        }
    }

    return $true;
}

function Write-Bookmarks {
    $profPath = [System.IO.Path]::GetDirectoryName($profile);
    $newPath = "$profPath\Jumps.json";
    $oldPath = "$profPath\Jumps.json.prev";

    if (Test-Path $oldPath) {
        del "$oldPath"
    }

    if (Test-Path $newPath) {
        ren "$newPath" "$oldPath"
    }

    ConvertTo-Json $global:bookmarks | Out-File $newPath

    $Global:JumpFileTime = (Get-Item $newPath).LastWriteTime;
}

function Invoke-Bookmark {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$jumpcat = '.'
    )

    if ($global:bookmarks.ContainsKey($jumpcat)) {
        cd $global:bookmarks[$jumpcat].ToString();
    }
    else {
        "Unknown jump target."
        "Type: 'jumps' to get a list of available bookmarks."
    }
}

function Get-Bookmarks {
    $en = $global:bookmarks.GetEnumerator();

    while ($en.MoveNext()) {
        "$($en.Key.PadRight(10)) -> $($en.Value)"
    }
}

Set-Alias jump   Invoke-Bookmark
Set-Alias jumps  Get-Bookmarks
Set-Alias marks  Get-Bookmarks
Set-Alias mark   New-Bookmark
Set-Alias unmark Remove-Bookmark
Set-Alias up Update-Profile
Set-Alias m Menu
Set-Alias clac CLACMenu
Set-Alias sf Screenfetch

#Load bookmarks from previous session.
Read-Bookmarks

############### Setup Parameter autocomplete Hack #################

<#
What this script does
1) Creates a scriptblock that gathers all AD information.  Gathered information is exported as a CSV in the temp directory
2) Start the scriptblock under a new thread so powershell does not hang.
3) Creates scriptblocks that imports the related CSV and created an autocomplete object.
4) Modify powershell autocomplete to run custom scriptblock when parameter is detected.
#>

#Script block to get AD object in a different thread and export results to a csv in the temp directory
$GetADObjectScriptBlock = {
    #Gathering all computers from local domain
    $ComputerTempCSV = "$env:TEMP\ALLDOMAINCOMPUTERS.csv"
    #Remove Previously created CSV's
    Remove-Item -Path $ComputerTempCSV -ErrorAction SilentlyContinue -Force
    #Create adsisearcher object
    $searcher = [adsisearcher]"(&(objectClass=Computer)(operatingSystem=*))"
    $searcher.PropertiesToLoad.Add("cn") | Out-Null
    $searcher.PropertiesToLoad.Add("operatingsystem") | Out-Null
    $searcher.PropertiesToLoad.Add("distinguishedname") | Out-Null
    #Loop through all results and export results
    $($searcher.FindAll()) | ForEach-Object {
        $currentObject = $_
        [Array]$propertiesList = $currentObject.Properties.PropertyNames
        $TempObj = New-Object PSObject
        $currentObject.Properties.PropertyNames | ForEach-Object {
            $currentProperty = $_
            $TempObj | Add-Member -MemberType NoteProperty -name $currentProperty -value ([string]$currentObject.Properties.Item($currentProperty))
        }
        #Export Results
        $TempObj | Export-Csv -Path $ComputerTempCSV -NoTypeInformation -Force -Append
    }

    #Gathering all users from local domain
    $UserTempCSV = "$env:TEMP\ALLDOMAINUSERS.csv"
    #Remove Previously created CSV's
    Remove-Item -Path $UserTempCSV -ErrorAction SilentlyContinue -Force
    #Create adsisearcher object
    $searcher = [adsisearcher]"(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
    $searcher.PropertiesToLoad.Add("samaccountname") | Out-Null
    $searcher.PropertiesToLoad.Add("displayname") | Out-Null
    $searcher.PropertiesToLoad.Add("physicaldeliveryofficename") | Out-Null
    $searcher.PropertiesToLoad.Add("title") | Out-Null
    $searcher.PropertiesToLoad.Add("department") | Out-Null
    $searcher.PropertiesToLoad.Add("mail") | Out-Null
    #Loop through all results and export results
    $($searcher.FindAll()) | ForEach-Object {
        $currentObject = $_
        [Array]$propertiesList = $currentObject.Properties.PropertyNames
        $TempObj = New-Object PSObject
        $currentObject.Properties.PropertyNames | ForEach-Object {
            $currentProperty = $_
            $TempObj | Add-Member -MemberType NoteProperty -name $currentProperty -value ([string]$currentObject.Properties.Item($currentProperty))
        }
        #Export Results
        $TempObj | Select-Object samaccountname, displayname, physicaldeliveryofficename, title, department, mail | Export-Csv -Path $UserTempCSV -NoTypeInformation -Force -Append
    }
}
Get-Job | Remove-Job -Force
Start-Job -ScriptBlock $GetADObjectScriptBlock | Out-Null

#Creating auto-complete computer script
$Completion_ComputerName = {
    Import-Csv -Path "$env:TEMP\ALLDOMAINCOMPUTERS.csv" | ForEach-Object {
        try {
            New-Object System.Management.Automation.CompletionResult $_.cn, $_.cn, 'ParameterValue', "$($_.operatingsystem) - $($_.distinguishedname)"
        }
        catch {}
    }
}

#Creating auto-complete -username script
$Completion_Username = {
    Import-Csv -Path "$env:TEMP\ALLDOMAINUSERS.csv" | ForEach-Object {
        Try {
            $currentUser = $_
            New-Object System.Management.Automation.CompletionResult $currentUser.samaccountname, $currentUser.samaccountname, 'ParameterValue', "($($currentUser.displayname)) - Office: $($currentUser.physicaldeliveryofficename) - Department: $($currentUser.department) - Title: $($currentUser.title)"
        }
        catch {}
    }
}

#Creating auto-complete -email script
$Completion_Email = {
    Import-Csv -Path "$env:TEMP\ALLDOMAINUSERS.csv" | ForEach-Object {
        try {
            $currentUser = $_
            New-Object System.Management.Automation.CompletionResult $currentUser.Mail, $currentUser.Mail, 'ParameterValue', "($($currentUser.displayname)) - Office: $($currentUser.physicaldeliveryofficename) - Department: $($currentUser.department) - Title: $($currentUser.title)"
        }
        catch {}
    }
}

$function:tabexpansion2 = $function:tabexpansion2 -replace 'End\r\n{', 'End { if ($null -ne $options) { $options += $global:options} else {$options = $global:options}'
#create CustomArgumentCompleters and NativeArgumentCompleters
$global:options = @{CustomArgumentCompleters = @{}; NativeArgumentCompleters = @{}}
#add each CustomArgumentCompleters
$global:options['CustomArgumentCompleters']['ComputerName'] = $Completion_ComputerName
$global:options['CustomArgumentCompleters']['Server'] = $Completion_ComputerName
$global:options['CustomArgumentCompleters']['Username'] = $Completion_Username
$global:options['CustomArgumentCompleters']['Mailbox'] = $Completion_Email
$global:options['CustomArgumentCompleters']['Email'] = $Completion_Email
$global:options['CustomArgumentCompleters']['EmailAddress'] = $Completion_Email
$global:options['CustomArgumentCompleters']['Identity'] = $Completion_Username

#This profile will load all .ps1 file found in the following folders.
$CustomModuleDirectory = @("E:\CLAC\Infrastructure\Powershell Cmdlets\Automated CLAC Processes",
    "E:\CLAC\Infrastructure\Powershell Cmdlets\Tools")


#Import all .ps1 from $CustomModuleDirectory
$CustomModuleDirectory | ForEach-Object {
    if (Test-Path -Path $_) {
        Get-ChildItem -path "$_\*" -Recurse -Include *.ps1 | ForEach-Object {
            $currentCmdlet = $_
            try {
                Import-Module $currentCmdlet.FullName -Force
            }
            catch {
                Write-Warning -Message "Failed to import $($currentCmdlet.Fullname) : $($_.Exception.Message)"
            }
        }
    }
    else {
        Write-Warning -Message "$_ does not exist.  Please ensure you have the correct directory set inside your powershell profile.ps1."
        Write-Warning -Message "Run '`$profile | Select-Object *' to see the file location of all your profiles."
    }
}
function CLACMenu {
    <#
.Synopsis
   Creates a visual menu of all custom CLAC CMDLETS.
.DESCRIPTION
   Creates a visual menu of all custom CLAC CMDLETS.
.EXAMPLE
   CLACMenu

   Lists menu.

.EXAMPLE
   CLACMenu -includedescription

   This menu and includes descriptions

.EXAMPLE
   CLACMenu -Type 'Active Directory Tools'

   Creates menu and only includes active directory tools.
#>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $false)]
        [switch]$includedescription = $false,

        [Parameter(Mandatory = $false)]
        $CMDLetDirectory = $CustomModuleDirectory
    )
    DynamicParam {
        $attributes = new-object System.Management.Automation.ParameterAttribute
        $attributes.Mandatory = $false

        $attributeCollection = new-object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $attributeCollection.Add($attributes)

        $arrSet = (Get-ChildItem -Path $CustomModuleDirectory -Directory).Name
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($arrSet)
        $AttributeCollection.Add($ValidateSetAttribute)

        $dynParam1 = new-object -Type System.Management.Automation.RuntimeDefinedParameter("Type", [string[]], $attributeCollection)

        $paramDictionary = new-object -Type System.Management.Automation.RuntimeDefinedParameterDictionary
        $paramDictionary.Add("Type", $dynParam1)

        return $paramDictionary
    }
    Begin {
        Write-Verbose -Message "Getting a list of the commands..."
        $CMDLetDirectory | ForEach-Object {
            $commandList += Get-ChildItem -path "$_\*" -Recurse -Include *.ps1 | Select-Object *, @{n = 'Type'; e = {"$($_.directory.Name)"}}
        }

        if ($PSBoundParameters['Type']) {
            Write-Verbose -Message "Filtering results to $($PSBoundParameters['Type'])"
            $commandList = $commandList | Where-Object { $PSBoundParameters['Type'].contains($_.Type)}
        }
    }
    Process {
        $script:b = -1
        $menu = New-Object PSobject
        if ($includedescription.IsPresent) {
            Write-Verbose -Message "-includedescription is present.  Gathering cmdlets and descriptions..."
            $menu = $commandList | Sort-Object -property Type, basename| Format-Table -AutoSize @{n = 'Number'; e = {$script:b++; $script:b}}, BaseName, @{name = 'Synopsis'; expression = { ((Get-Help ($_.BaseName)).Synopsis) }}, Type
        }
        else {
            $menu = $commandList | Sort-Object -property Type, basename| Format-Table -AutoSize @{n = 'Number'; e = {$script:b++; $script:b}}, BaseName, Type
        }

        return $menu
    }
    End {
        Write-Host -ForegroundColor Green 'Run "Get-Menu -IncludeDescription" for a menu with command descriptions.'
    }
}

cl
