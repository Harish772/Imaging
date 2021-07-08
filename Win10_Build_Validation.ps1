Win10_Build_Validation2107_YOURAWESOMECOMPANY.ps1.txt

#20170908 -  - Initial build for Win10
#20170912 -  - added Bios version compare
#20180130 - - changed source paths to wil-01\Users\Windows OS Development
#20180322 -  - edits for 1805; unattended execution at end of OS Deployment task sequence
#20200218 -  - added Windows release info ($osrls)
#20200324 - - replacing YOUROLDAWESOMECOMPANY with YOURAWESOMECOMPANY

#. "$PSScriptRoot\function.ps1"
Start-Transcript -Path 'c:\ProgramData\YOURAWESOMECOMPANY\Validation.log' -Force
function Html-output {
    Param(
        $Success,
        $Unsuccess,
        $Message
    ) 
    Process {

        if($Success){
 
            "<font style='color:#ffffff;font-size:100%'>&#9745; $Message </font>" | out-file $outfile -Append
            '<br/>'| out-file $outfile -append 
        }
        if($Unsuccess){
            "<font style='color:#ff0000;font-size:100%'>&#9746; $Message </font>" | out-file $outfile -Append
            '<br/>'| out-file $outfile -append
        }
    }
}#End Function 
Function Registry-check{

    Param(
          $Path,
		  $Message
		  
    )
    Process {
            if ((Test-path $Path) -eq $true){

                "<font style='color:#ffffff;font-size:100%'>&#9745; $Message </font>" | out-file $outfile -Append
                        '<br/>'| out-file $outfile -append 
            }
            else {
                "<font style='color:#ff0000;font-size:100%'>&#9746; $Message </font>" | out-file $outfile -Append
                 '<br/>'| out-file $outfile -append
            }
    }
}

#Initial Global Values
$date = Get-date
$Nobio = 0
$nodvr = 0
$NoApp = 0
#change $MYBLD to match the current build number
$MYBLD = "2107"

Write-host "Gathering machine information..."

$model = (Get-WMIObject win32_computersystemproduct).name
$wsid = (Get-WMIObject win32_computersystemproduct).Identifyingnumber
[string]$wsid = ("WS-" +($wsid.split(" ")[-6,-5,-4,-3,-2,-1])).Replace(" ","")
$make = (Get-WMIObject win32_computersystemproduct).vendor
$alias = (Get-WMIObject win32_computersystemproduct).version
$bio = (get-wmiobject Win32_bios).name
$DG = Get-ItemPropertyvalue 'HKLM:\SOFTWARE\YOURAWESOMECOMPANY\OSDeployment' 'Deployment Group'
$PrimaryUserID = Get-ItemPropertyvalue 'HKLM:\SOFTWARE\YOURAWESOMECOMPANY\OSDeployment' 'Primary UserID'
$bld = Get-ItemPropertyvalue 'HKLM:\SOFTWARE\YOURAWESOMECOMPANY\OSDeployment' 'Task Sequence Name'
$osver = Get-ItemPropertyvalue 'HKLM:\SOFTWARE\YOURAWESOMECOMPANY\OSDeployment' 'Windows Version'
$osrls = (Get-ItemProperty -Path c:\windows\system32\hal.dll).VersionInfo.productVersion 
$arch = (get-wmiobject -class win32_operatingsystem).osarchitecture
$ResourceFileBIOS = "\\wil-dse01\Users\Windows OS Development\Win10\BIOS_UEFI\$model.txt"
$ResourceFileDrivers = "\\wil-dse01\Users\Windows OS Development\Win10\$MYBLD\Driver_layer\$model.txt"
$JasonFile = "$PSScriptRoot\Applist.json"

Write-host "Starting to write the output file..."
$outfile = "c:\ProgramData\YOURAWESOMECOMPANY\branding\YOURAWESOMECOMPANYInfo.html"
#$outfile = "c:\temp\YOURAWESOMECOMPANYInfo.html"

"<html>" | out-file $outfile -force
'<body bgcolor="#000000" text="ffffff">' | out-file $outfile -append
"<h1 align='center'>YOURAWESOMECOMPANY OS Deployment Validation Report for $BLD</h1>" | out-file $outfile -append
#"<h1 align='center'>BB&T OS Deployment Validation Report for Windows 10 Release $MYBLD</h1>" | out-file $outfile -append

"<font style='color:#ffffff;font-size:120%'>Validation Date: $date</font>" | out-file $outfile -append
'<br/>'| out-file $outfile -append

"<font style='color:#ffffff;font-size:120%'>Validation Resources:</font>" | out-file $outfile -append
'<ul>'| out-file $outfile -append
"<li><font style='color:#ffffff;font-size:100%'>$ResourceFileBIOS</font></li>" | out-file $outfile -Append
"<li><font style='color:#ffffff;font-size:100%'>$ResourceFileDrivers</font></li>" | out-file $outfile -Append
"<li><font style='color:#ffffff;font-size:100%'>$JasonFile</font></li>" | out-file $outfile -Append
'</ul>'| out-file $outfile -append


"<h2>General Information</h2>" | out-file $outfile -append

 If ("$wsid" -like $env:COMPUTERNAME){
    "<font style='color:#ffffff;font-size:120%'>$env:COMPUTERNAME</font>" | out-file $outfile -append  
 }

 Elseif ($env:COMPUTERNAME -like "MININT-*" ){

         "<font style='color:#ff4000;font-size:120%'>$env:COMPUTERNAME</font><font style='color:#ff4000;font-size:100%'> (Should be $wsid)</font>" | out-file $outfile -append  
}
 Else {
    "<font style='color:#ffff00;font-size:120%'>$env:COMPUTERNAME</font><font style='color:#ffff00;font-size:100%'> (Should be $wsid)</font>" | out-file $outfile -append  
}
'<br/>'| out-file $outfile -append

"<font style='color:#ffffff;font-size:120%'>$make $alias ($model)</font>" | out-file $outfile -append
'<br/>'| out-file $outfile -append
"<font style='color:#ffffff;font-size:120%'>$osver ($osrls)</font>" | out-file $outfile -append
'<br/>'| out-file $outfile -append
"<font style='color:#ffffff;font-size:120%'>OSD Task Sequence:$bld</font>" | out-file $outfile -append
'<br/>'| out-file $outfile -append
"<font style='color:#ffffff;font-size:120%'>OS Architecture:  $arch</font>" | out-file $outfile -append
'<br/>'| out-file $outfile -append
"<font style='color:#ffffff;font-size:120%'>Deployment Group: $DG</font>" | out-file $outfile -append
'<br/>'| out-file $outfile -append
"<font style='color:#ffffff;font-size:120%'>Primary User:     $PrimaryUserID</font>" | out-file $outfile -append
'<br/>'| out-file $outfile -append

write-host "Checking BIOS..."
$Bios = GC $ResourceFileBIOS
"<h2>BIOS</h2>" | out-file $outfile -append
If ($bio -eq $null ) {

    Write-host "BIOS Configuration was NOT found!" -ForegroundColor "red"
    "<font style='color:#ff0000;font-size:100%'>&#9744;$bios</font>" | out-file $outfile -Append
    '<br/>'| out-file $outfile -append
    $Nobio = 1

}
If ($nobio -eq 0){ 
    If ($bio -like $bios){
        
        Html-output -Success $true -Message $bio 
    }
    Else {

        Write-host "BIOS is NOT correct!" -ForegroundColor "yellow"
        Html-output -Unsuccess $true -Message $bio
       
    }

}

write-host "Checking Drivers..."
$Drivers = GC $ResourceFileDrivers
"<h2>Drivers</h2>" | out-file $outfile -append

foreach ($driver in $drivers){

    $array = $Driver.split(';')
    $dvr = $array[0]
    $ver = $array[1]

    $dumvar1 = Get-WmiObject Win32_PnPSignedDriver| select devicename, driverversion | where {$_.devicename -like $dvr}
    if ($dumvar1 -eq $null ) {

        Write-host "Driver was NOT found: $dvr" -ForegroundColor "red"              
        "<font style='color:#ff0000;font-size:100%'>&#9744;$dvr $ver</font>" | out-file $outfile -Append
        '<br/>'| out-file $outfile -append
        $Nodvr = 1                        
    }
    IF ($nodvr -eq 0){ 

        If ($dumvar1.driverversion -like $ver){

            $tst = $dumvar1.driverversion
             Html-output -Success $true -Message "$dvr $tst"

        }
        Else {

            $tst = $dumvar1.driverversion
            Write-host "Driver is NOT correct: $dvr $dumvar1.driverversion (Required is $ver)" -ForegroundColor "yellow"
            Html-output -Unsuccess $true -Message "$dvr $dumvar1.driverversion (Required is $ver)"

        }

    }

    #reset for next loop
    $nodvr = 0
    $tst ={}

}


################################################################################################################

write-host "Checking Applications..."
#$Drivers = GC $ResourceFileDrivers
"<h2>Applications</h2>" | out-file $outfile -append

try {

      #$JasonContent = Get-Content -Path "$PSScriptRoot\Applist.json" -Raw -ErrorAction stop | ConvertFrom-Json
      #$ResourceFileDrivers = "\\wil-01\Users\Windows OS Development\Win10\$MYBLD\Driver_layer\$model.txt"
      
      $JasonContent = Get-Content -Path "$PSScriptRoot\Applist.json" -Raw -ErrorAction stop | ConvertFrom-Json
      
	  #Declaring List of App Names into Variable 
      $ProgramList = $JasonContent.InstallApplications
      
	  #Declaring Version information into variable 
      $ApplicationVersion = $JasonContent.Version

      #Declare BuiltinappsRemoval - Verify the existes of built in apps. 
      $BuiltinappsRemoval = $JasonContent.BuiltinappsRemoval

      #Declare Builtapp addition to the target OS 
      $BuiltinappsAdd = $JasonContent.BuiltinappsAdd

      #Declare Enivronment variable in json file
      $EnvironmentVariable = $JasonContent.EnvironmentVariable

      #Custom Applications - Sysmon, CMtrace
      $CustomApp = $JasonContent.CustomApp

      #Verify the folders or files exists 
      $Dir = $JasonContent.Dir
      
      #Required Optional Features 
      $RequiredFeatures = $JasonContent.RequiredFeatures
 
} #End try Block 
catch {
       
       #Log-Message 'Not able to fetch the data from Json file'
}#End catch Block
    
 ForEach ($Program in $ProgramList){
    
    # Checks installed programs for products that contain provided keywords in the name
    Function Get-InstalledApps{

     if ($ProgramList) {
       
        $Regpath = @( 
                        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
                     )                   
    }#End If loop 
    
    #Reteriving the required properties from Registry

    Get-ItemProperty $Regpath | .{Process{If($_.DisplayName) { $_ } }} | Select DisplayName, InstallDate, DisplayVersion |Sort DisplayName

    }#End Function 

    #Sorting the data as per requirement
    $Result = Get-InstalledApps | Where {($_.DisplayName -like "$Program") }

    
    # output results to the log
    If ($Result) {
        #Reteriving the Validated version of Applications
        $Version = $Result.DisplayVersion
		
		#Registering the application Name into variable 
        $Dispalyname = $Result.DisplayName

        #Verifying the application Name existence with installted application list
        $ProgramList | ForEach-Object { 
		       #IF app name match enter into the foreach loop
              if ($Dispalyname -match $_ ){
                       #If app name and version matched assign the version into a variable for further check. 
                       $ApplicationVersion | ForEach-Object {
                          if ($Version -match $_){
                                   
                                   $A = $Version
        
                          }#end if loop 
                          }#end foreach-object
						  #If both Application Name and version gets matched print the output to logfile.
                          if (($Dispalyname -match $_ ) -and  ($A -match $Version)){ 
                            
                            Html-output -Success $true -Message "$_"
 ###                           Log-Message "$Program = Installed"
							$i = $i +1
                          } #end if
                          elseif (($Dispalyname -match $_ ) -and  ($A -notmatch $Version))  {
                         
                            Html-output -Unsuccess $true -Message "$_"

                          }#End Else If
                }#End If Loop 
            }#End For-eachobject 
    } #End of If loop
	Else {

         Html-output -Unsuccess $true -Message "$Program"
		$i = $i+1
    }#End of Else 
    }#End of Foreach Loop 
########################Verify the existence of Sysmon and CMtrace ###########################

$CustomApp | ForEach-Object {
    if ((Test-Path -Path $_) -eq $false){
        Html-output -Unsuccess $true -Message $_ 
    }
    else {
       Html-output -Success $true -Message $_ 

    }
}

########################Validate XPSViewer is installed###########################
$Program = "XPS Viewer"
$i = $i+1
$XPSVIewer = (Get-WindowsCapability -Online -Name "*XPS*").State
IF( $XPSVIewer -eq "Installed") {
 Html-output -Success $true -Message "XPSViewer" 

}
Else {
Html-output -Unsuccess $true -Message "XPSViewer" 

}

########################Check for Built in apps Removal stats###########################

$InstalledAppx = (Get-AppxPackage *).name
$BuiltinappsRemoval | ForEach-Object {

    if ($_ -in $InstalledAppx){

    Html-output -Unsuccess $true -Message $_ 
    }#End If 
}#End foreach 

########################Veirfy the status of Windy applicaiotn installation.###########################
 $BuiltinappsAdd | ForEach-Object {

    if ($_ -notin $InstalledAppx){
        Html-output -Unsuccess $true -Message $_    
    }#End If 
    else{
        Html-output -Success $true -Message $_ 
    }
}#End foreach 

########################Custom Settings.###########################

write-host "Checking Custom Settings..."
"<h2>Custom Settings</h2>" | out-file $outfile -append
#########################Verify the environment variables on target machines###########################
$Environmentvariables = (Get-ChildItem -Path ENV:).name
$EnvironmentVariable | ForEach-Object {
    if ($_ -notin $Environmentvariables){
         Html-output -Unsuccess $true -Message $_ 
    }#End If 
    else {
        Html-output -Success $true -Message $_ 
    }
}#End foreach 
##########################Verify the existence of the directories###########################


$Dir | ForEach-Object {
    if ((Test-Path -Path $_) -eq $false){
        Html-output -Unsuccess $true -Message $_ 
    }
    else {
       Html-output -Success $true -Message $_ 

    }
}
###########################Verify the existance of RSAT Source files ###########################
<#if((test-path -Path 'C:\ProgramData\FODv1903x64_RSAT') -eq $true){
 Html-output -Success $true -Message "RSAT"

}
else {
   Html-output -Unsuccess $true -Message "RSAT" 
}#>

Registry-check -Path 'C:\ProgramData\FODv1903x64_RSAT' -Message 'RSAT'

###########################Verifying the device guard ###########################

 
$Value = Get-Content -Path 'C:\Windows\ccm\Logs\DeviceGuardCheckLog.log'| Where-Object { ($_| select-string 'Please reboot the machine, for settings to be applied.')}
if ($Value){
     Html-output -Success $true -Message "Device Gaurd"
}
else {
        Html-output -Unsuccess $true -Message "Device Gaurd" 

}
###########################Verfying the windows optional features ###########################
$WindowsFeature= (Get-WindowsOptionalFeature -Online | Where-Object {$_.state -eq 'enabled'}).FeatureName


$RequiredFeatures | ForEach-Object {

if ($_ -in $WindowsFeature){
     Html-output -Success $true -Message $_ 


}
else {
     Html-output -Unsuccess $true -Message $_ 

}
}
########################Check for TPM and Bitlocker stats###########################

IF ((Get-WmiObject -Namespace "root\CIMV2\Security\MicrosoftTpm" -Class Win32_TPM) -eq "") {
$TPM = (Get-WmiObject -Namespace "root\CIMV2\Security\MicrosoftTpm" -Class Win32_TPM).SelfTest()
}

$Bitlocker = (Get-BitLockerVolume -MountPoint C:).KeyProtector.KeyProtectortype
If ($Bitlocker -contains "Tpm") {


           Html-output -Success $true -Message "Bitlocker" 

}
Else {
     Html-output -Unsuccess $true -Message "Bitlocker" 

}
#########################Check for OSD Tattoo ###########################
$OSDTattoo = 'HKLM:\Software\YOURAWESOMECOMPANY\OSDeployment'
If ((test-Path -Path $OSDTattoo)-eq $true) {
	Html-output -Success $true -Message "RegKey OSDeployment Tattoo" 
}
Else {
     Html-output -Unsuccess $true -Message "RegKey OSDeployment Tattoo" 
}

###########################Check for Reconcile File ################################
$Reconcileme = 'C:\ProgramData\YOURAWESOMECOMPANY\reconcileme.exe'
If ((test-Path -Path $OSDTattoo)-eq $true) {
	Html-output -Success $true -Message "Reconcileme" 
}
Else {
     Html-output -Unsuccess $true -Message "Reconcileme" 
}

###########################Check for Removed Defender, Removed Defender Setup, Removed Consumer Features, Removed People Taskbar, Set Allow Trusted Apps ##########
$DisableAntiSpyware = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Name "DisableAntiSpyware"
$DisableWindowsConsumerFeatures = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures"
$HidePeopleBar = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HidePeopleBar"
$AllowAllTrustedApps = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "AllowAllTrustedApps"
$ShowRunAsDifferentUser = Get-ItemPropertyValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "ShowRunAsDifferentUserInStart"	
$Array = @(
			"$DisableAntiSpyware 'DisableAntiSpyware'",
			"$DisableWindowsConsumerFeatures 'DisableWindowsConsumerFeatures'",
			"$HidePeopleBar 'HidePeopleBar'",
			"$AllowAllTrustedApps 'AllowAllTrustedApps'",
			"$ShowRunAsDifferentUser 'ShowRunAsDifferentUser'"
	)

$Array | ForEach-Object {

		if($_ -like "1*"){

			Html-output -Success $true -Message $_
		}
		else {

			Html-output -Unsuccess $true -Message $_
		}
}

###########################Check for ShowFileExtensions ##############################################################

$ShowFileExtensions = Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt"
if($ShowFileExtensions -eq '0'){

			Html-output -Success $true -Message "ShowFileExtensions"
		}
		else {

			Html-output -Unsuccess $true -Message "ShowFileExtensions"  
		}
###########################Check for Set OSManagedAuthLevel ##############################################################
$OSManagedAuthLevel = Get-ItemPropertyValue -Path "HKLM:\Software\Policies\Microsoft\TPM" -Name "OSManagedAuthLevel"
if($ShowFileExtensions -eq '2'){

			Html-output -Success $true -Message "OSManagedAuthLevel"
		}
		else {

			Html-output -Unsuccess $true -Message "OSManagedAuthLevel"  
		}
		
<########################Validation TFC Variables are in place###########################

$TFCLogDir = (Get-Item Env:TFCLogDir).Value
If ($TFCLogDir -ne "") {
    $TFCEnvVariables="True"
    }
Else {
    $TFCEnvVariables="False"
    }


IF ($TFCEnvVariables="True") {
    $TFCCommonDir = (Get-Item Env:TFCCommonDir).Value
    If ($TFCCommonDir -ne "") {
        $TFCEnvVariables="True"
        }
    Else {
        $TFCEnvVariables="False"
        }
}

IF ($TFCEnvVariables="True") {
    $TFCDSEDir = (Get-Item Env:TFCDSEDir).Value
        If ($TFCDSEDir -ne "") {
        $TFCEnvVariables="True"
        }
    Else {
        $TFCEnvVariables="False"
        }
}

    
             Html-output -Success $true -Message "TFCEnvVariables=$TFCEnvVariables"


<########################Validate OneDrive is installed###########################
$Program = "OneDrive"
$i = $i+1
Import-Module OneDriveLib.dll
$ODStatus = Get-ODStatus

IF ($ODStatus -eq "") {
           Html-output -Success $true -Message "RemoveOneDrive "

#Log-Message "OneDrive = True"
}
Else {

             Html-output -Unsuccess $true -Message "RemoveOneDrive"

}#>
###############Verify OneDrive, XBox Gamebar, Your Phone shorcuts not present##################
$UserName = $env:UserName
$OneDiveLNK = Test-Path ("C:\Users\" + $UserName + "\Appdata\Roaming\Microsoft\Windows\Start Menu\Programs\Onedrive.lnk")
$XboxLNK = Test-Path ("C:\Users\" + $UserName + "\Appdata\Roaming\Microsoft\Windows\Start Menu\Programs\Onedrive.lnk")
$PhoneLNK = Test-Path ("C:\Users\" + $UserName + "\Appdata\Roaming\Microsoft\Windows\Start Menu\Programs\Onedrive.lnk")
$Program = "One Drive Shorct"
$i = $i+1
If ($OneDiveLNK -eq $false){
        Html-output -Success $true -Message "Onedrive Shortcut is removed"
        }
        else {
           Html-output -Unsuccess $true -Message "Onedrive Shortcut is not removed"

        }
$Program = "XBox Shorct"
$i = $i+1
If ($XboxLNK -eq $false){
        Html-output -Success $true -Message "XboxLNK Shortcut is removed"
        }
        else {
           Html-output -Unsuccess $true -Message "XboxLNK Shortcut is not removed"

        }
       
$Program = "Your Phone"
$i = $i+1
If ($PhoneLNK -eq $false){
        Html-output -Success $true -Message "PhoneLNK Shortcut is removed"
        }
        else {
           Html-output -Unsuccess $true -Message "PhoneLNK Shortcut is not removed"

        }

##############Verify .Net Version installed###############

$Program = ".Net Installation Plus Versions"
$i = $i+1
$Net = (get-childitem -path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP").PSChildName
If ($Net -eq "") {

                     Html-output -Unsuccess $true -Message ".Net Installed"

}
Else {

    Html-output -Success $true -Message ".Net Installed"

Foreach ($NetV in $Net) {

        Html-output -Success $true -Message "Version = $NetV"

}
}

######################Checking Logon RegistryKey########################
$Program = "Logon Registry Key"
$i = $i+1
$LogonScript = Get-ChildItem -Path "HKLM:\Software\WOW6432Node\YOUROLDAWESOMECOMPANY\LogonScript"
If ($LogonScript -eq "") {

                             Html-output -Unsuccess $true -Message "LogonScript Registry Key"

}
Else {

                Html-output -Success $true -Message "LogonScript Registry Key"

}

######################BIOS-Firmware mode is UEFI########################
#UEFI 			UEFI native				UEFI native
#with CSM		Secure boot enabled		Secure boot disabled
#	1				0						1
$Program = "UEFI"
$i = $i+1
$UEFI = (Get-secureBootUEFI -Name SetupMode).Bytes
If ($UEFI -eq "0") {

                        Html-output -Success $true -Message "UEFI"

}
Else {
                                     Html-output -Unsuccess $true -Message "UEFI coud be enable but with CSM or SecreBoot is Dissabled"

}

######################Windows Defender is Disabled########################
$Program = "Windows Defender"
$i = $i+1
$Defender = (Get-MpPreference).DisableRealtimeMonitoring
$Program = "Windows Defender Policy Key"
$i = $i+1
$DefenderRegKey = (get-childitem -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender").DisableAntiSpyWare
If ($Defender -eq "False") {

                 Html-output -Unsuccess $true -Message "Windows Defender Dissable"

}
Else {

     Html-output -Success $true -Message "Windows Defender Dissable , The Disable Realtime monitoring is set to True"

}

IF($DefenderRegKey -eq "1"){

             Html-output -Success $true -Message "Windows Defender Dissable policy RegKey = A policy key has been fond and is set to disable Windows Defender"

}

######################Adobe Reader set as default PDF reader########################
$Program = "Acrobat Reader set as Default"
$i = $i+1
$AcroRead = (Get-ChildItem HKLM:\SOFTWARE\Classes\.pdf\OpenWithList).name
IF($AcroRead -eq "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.pdf\OpenWithList\AcroRd32.exe") {

        Html-output -Success $true -Message "Acrobat Reader Default"

}
Else {

        Html-output -Unsuccess $true -Message "Acrobat Reader Default"
}

######################Device Guard is enabled########################
#VirtualizationBasedSecurityStatus. This field indicates whether VBS is enabled and/or running.
#0. VBS is not enabled.
#1. VBS is enabled but not running.
#2. VBS is enabled and running.
$Program = "Device Guard Status"
$i = $i+1
$VBS = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).VirtualizationBasedSecurityStatus
IF ($VBS -eq "2"){

        Html-output -Success $true -Message "Device Guard"

}
Else {

                Html-output -Unsuccess $true -Message "Device Guard"

}
########################################Log file Review ###################################################
write-host "Reviewing SMSTS Log files"
"<h2>LOG Review - SMSTS.LOG</h2>" | out-file $outfile -append
$JasonContent = Get-Content -Path "$PSScriptRoot\Applist.json" -Raw -ErrorAction stop | ConvertFrom-Json
$WindowsLogFile = (Get-ChildItem -path 'C:\Windows\CCM\Logs' | Where-Object{$_.Name -like "SMSTS*"}).FullName
#####################Troubleshooting Data###########
<#$TestData = (Get-ChildItem -Path 'c:\'-Hidden).Name
$NonHidden =  (Get-ChildItem -Path 'c:\').Name
Write-Host $NonHidden
Write-Host $TestData 
$ACL = Get-Acl -Path 'C:\_SMSTaskSequence' | select *
Write-Host $ACL
Write-Host $WindowsLogFile
#>

########################################################################

if((Test-Path -path 'C:\_SMSTaskSequence') -eq $true){
$SmstsfolderLogfiles = (Get-ChildItem -path 'C:\_SMSTaskSequence' -Recurse -Force | Where-Object{$_.Name -like "SMSTS*"}).FullName
Write-Host $SmstsfolderLogfiles
}
$SmstsfolderLogfiles | ForEach-Object{
    $LogfilePath = $_ 
    $Actions = $JasonContent.Actions
    Foreach ($Action in $Actions){
            $SelectString =(Get-Content -Path "$LogfilePath" | Select-String -Pattern $Action -Encoding ascii)
               <# if(!$SelectString){
                                    "<font style='color:#ffffff;font-size:100%'>&#9745;No common failures found in $LogfilePath - $Action </font>" | out-file $outfile -Append
                                            '<br/>'| out-file $outfile -append
          
                                    }#>
            $SelectString | ForEach-Object{            
                                if ($_){
                                        $SplitData = (($_-split("]"))[0]).split("[")[2]
                                        $Output = "'" + "$SplitData" + "'" 
                                        "<font style='color:#ff0000;font-size:100%'>&#9746;Found ERROR in -$LogfilePath - $Output </font>" | out-file $outfile -Append
                                         '<br/>'| out-file $outfile -append 
                                }
            }
	}
}

'</body>'| out-file $outfile -append

'</html>'| out-file $outfile -append

Stop-Transcript

