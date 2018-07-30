$ProVersion = "v0.0.1"
$ProName = "| TekPS $ProVersion |"
<#
Author: Alex Gust aka TekGoose

Update Notes:
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

function PrintMenu {

    Write-Host(" ----------------------- ")
    Write-Host("$ProName")
    Write-Host(" ----------------------- ")
    Write-Host('Type "GUI" to launch GUI interface!')
    Write-Host("")
    Write-Host("Command             Function")
    Write-Host("-------             --------")
    Write-Host -ForegroundColor Red ("cl                  Clear Shell and Reprint Command Menu")
    Write-Host -ForegroundColor Red ("CLACMenu            Retrieve CLAC custom cmdlets")
    Write-Host("CheckProcess        Retrieve System Process Information")
    Write-Host("CrossCertRm         Remove Inoperable Certificates")
    Write-Host("GPR                 Group Policy (Remote)")
    Write-Host("HuntUser            Query SCCM For Last System Logged On By Specified User")
    Write-Host("InstallApplication  Silent Install EXE, MSI, or MSP files")
    Write-Host("JavaCache           Clear Java Cache")
    Write-Host("LastBoot            Get Last Reboot Time")
    Write-Host("NetMSG              On-screen Message For Specified Workstation(s)")
    Write-Host("NewADuser           Create New Active Directory Users From SAAR Forms")
    Write-Host("Nithins             Opens Nithin's SCCM Client Tool")
    Write-Host("RDP                 Remote Desktop")
    Write-Host("REARMOffice         Rearm Office 2013 Activation")
    Write-Host("REARMWindows        Rearm Windows 7 OS Activation")
    Write-Host("Reboot              Force Restart")
    Write-Host("RmPrint             Clear Printer Drivers")
    Write-Host("RmUserProf          Clear User Profiles")
    Write-Host("SCCM                Active Directory/SCCM Console")
    Write-Host("SWcheck             Check Installed Software")
    Write-Host("SYS                 All Remote System Info")
    Write-Host("UpdateProfile       Update PowerShell Profile (Will Overwrite Current Version & Any Changes)")
    Write-Host("")
    Write-Host("")
    Write-Host -ForegroundColor Green "Beast mode active. Go get 'em, tiger."
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
    PrintMenu
}#End cl

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

function UpdateProfile {
<#
.SYNOPSIS
    Update PowerShell profile to current repository content.

.DESCRIPTION
    Update PowerShell profile to current repository content.

.EXAMPLE
    UpdateProfile
#>

    $NetworkLocation = "$env:USERPROFILE\OneDrive\_VS\GitHub\turbo-octo-goggles\Custom PS Profile\profile.ps1"
    $MyDocuments = [environment]::getfolderpath("mydocuments") + "\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
    $MyDocuments2 = [environment]::getfolderpath("mydocuments") + "\WindowsPowerShell\Profile.ps1"
    $MyDocuments3 = [environment]::GetFolderPath("mydocuments") + "\WindowsPowerShell\Microsoft.VSCode_profile.ps1"

    #Overwrite current $Profile for PowerShell and PowerShell ISE
    Copy-Item -path "$NetworkLocation" -destination "$MyDocuments" -Force
    Copy-Item -path "$NetworkLocation" -destination "$MyDocuments2" -Force
    Copy-Item -path "$NetworkLocation" -destination "$MyDocuments3" -Force

    #Reload PowerShell
    Powershell

}#End UpdateProfile

############### Setup Parameter autocomplete Hack #################

<#
What this script does
1) Creates a scriptblock that gathers all AD information.  Garthered information is exported as a CSV in the temp directory
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
        $TempObj | Select-Object samaccountname, displayname, physicaldeliveryofficename, title, department,mail | Export-Csv -Path $UserTempCSV -NoTypeInformation -Force -Append
    }
}
Get-Job | Remove-Job -Force
Start-Job -ScriptBlock $GetADObjectScriptBlock | Out-Null

#Creating auto-complete computer script
$Completion_ComputerName = {
    Import-Csv -Path "$env:TEMP\ALLDOMAINCOMPUTERS.csv" | ForEach-Object {
        try {
            New-Object System.Management.Automation.CompletionResult $_.cn, $_.cn, 'ParameterValue',"$($_.operatingsystem) - $($_.distinguishedname)"
        } catch {}
    }
}

#Creating auto-complete -username script
$Completion_Username = {
    Import-Csv -Path "$env:TEMP\ALLDOMAINUSERS.csv" | ForEach-Object {
        Try {
            $currentUser = $_
            New-Object System.Management.Automation.CompletionResult $currentUser.samaccountname, $currentUser.samaccountname, 'ParameterValue',"($($currentUser.displayname)) - Office: $($currentUser.physicaldeliveryofficename) - Department: $($currentUser.department) - Title: $($currentUser.title)"
        } catch {}
    }
}

#Creating auto-complete -email script
$Completion_Email = {
    Import-Csv -Path "$env:TEMP\ALLDOMAINUSERS.csv" | ForEach-Object {
        try {
            $currentUser = $_
            New-Object System.Management.Automation.CompletionResult $currentUser.Mail, $currentUser.Mail, 'ParameterValue',"($($currentUser.displayname)) - Office: $($currentUser.physicaldeliveryofficename) - Department: $($currentUser.department) - Title: $($currentUser.title)"
        } catch {}
    }
}

$function:tabexpansion2 = $function:tabexpansion2 -replace 'End\r\n{','End { if ($null -ne $options) { $options += $global:options} else {$options = $global:options}'
#create CustomArgumentCompleters and NativeArgumentCompleters
$global:options = @{CustomArgumentCompleters = @{};NativeArgumentCompleters = @{}}
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
    }
}

#Run get menu function with default values.
Write-Host -ForegroundColor Green 'Run "Get-Menu -IncludeDescription" for a menu with command descriptions.'

cl