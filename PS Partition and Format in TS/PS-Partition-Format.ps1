<#
    Name:   PSPartionAndFormat.ps1
    Usage:  Replaces Format and Partion steps (BIOS & UEFI) in ConfigMgr TS (OSD)
            - Possible to run as PS Inline script
    Acknowledment:
            Based on the partition schema blogged by Gary Block and Mike Terrill:
            https://garytown.com/osd-partition-setup-mike-terrill-edition-the-optimized-way
    Version: 1.1
    Date: 2019-07-17
#>

# Log in CMTrace format

function WriteLog {
    param(
    [Parameter(Mandatory)]
    [string]$LogText,
    [Parameter(Mandatory=$true)]
    $Component,
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('Info','Warning','Error','Verbose')]
    [string]$Type,
    [Parameter(Mandatory)]
    [string]$LogFileName,
    [Parameter(Mandatory)]
    [string]$FileName
    )

    switch ($Type)
    {
        "Info"      { $typeint = 1 }
        "Warning"   { $typeint = 2 }
        "Error"     { $typeint = 3 }
        "Verbose"   { $typeint = 4 }
    }

    $time = Get-Date -f "HH:mm:ss.ffffff"
    $date = Get-Date -f "MM-dd-yyyy"
    $ParsedLog = "<![LOG[$($LogText)]LOG]!><time=`"$($time)`" date=`"$($date)`" component=`"$($Component)`" context=`"`" type=`"$($typeint)`" thread=`"$($pid)`" file=`"$($FileName)`">"
    $ParsedLog | Out-File -FilePath "$LogFileName" -Append -Encoding utf8
}

# Create Com objects

$tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment
$tsUI = New-Object -COMObject Microsoft.SMS.TsProgressUI

# Detect whether Legacy or EUFI boot is used

$IsUefi = $tsenv.Value("_SMSTSBootUEFI").ToLower().Equals("true")

# Declare and define variables

$Self = "PSPartionAndFormat.ps1"
$LogPath = $tsenv.Value("_SMSTSLogPath")
$LogFile = "$LogPath\Onevinn." + $Self.Replace(".ps1", ".log")
$OrgName = $tsenv.Value("_SMSTSOrgName")
$TSName = $tsenv.Value("_SMSTSPackageName")
$CurrStepName = $tsenv.Value("_SMSTSCurrentActionName")

# Helper Function to feed ShowActionProgress, less arguments

function Show ([string]$Action, [int]$Percentage){
    $tsUI.ShowActionProgress("$OrgName", "$TSName", $null, "$CurrStepName", 0, 0, "$Action", $Percentage, 100)
}

# Function to create script file and execute Diskpart.exe

function RunDP ([string]$DP, [string]$Log, [int]$Percentage) {
    $DP | Out-File -FilePath "diskpart.txt" -Encoding ascii -Force
    Start-Process -FilePath "diskpart.exe" -ArgumentList @("/S diskpart.txt") -WindowStyle Hidden -Wait -EA Stop
    WriteLog -LogFileName "$LogFile" -Component "RunPowerShellScript" -FileName "$Self" -LogText "$Log" -Type Info
    Show -Action  "$Log" -Percentage $Percentage
    Start-Sleep -Milliseconds 400
}

WriteLog -LogFileName "$LogFile" -Component "RunPowerShellScript" -FileName "$Self" -LogText "Script and Com initiated, log started" -Type Info

# Legacy

if (!$IsUefi) {

WriteLog -LogFileName "$LogFile" -Component "RunPowerShellScript" -FileName "$Self" -LogText "Creating legacy disk" -Type Info
Show -Action  "Creating legacy disk" -Percentage 5
Start-Sleep -Milliseconds 1000

$DP1 =
@"
select disk 0
clean
create partition primary size=350
assign letter=S
format quick fs=ntfs label="System Reserved"
active
"@

RunDP -DP "$DP1" -Log "Created and formated 'System reserved' partition" -Percentage 30

$DP2 =
@"
select disk 0
create partition primary
assign letter=C
format fs=ntfs quick label="Windows"
shrink desired=984 minimum=984
"@

RunDP -DP "$DP2" -Log "Created and formated 'Windows' partition" -Percentage 65

$DP3 =
@"
select disk 0
create partition primary
format quick fs=ntfs label="Recovery"
set id=27
"@

RunDP -DP "$DP3" -Log "Created and formated 'Recovery' partition" -Percentage 95
}

# UEFI

if ($IsUefi) {

WriteLog -LogFileName "$LogFile" -Component "RunPowerShellScript" -FileName "$Self" -LogText "Creating UEFI disk" -Type Info
Show -Action  "Creating UEFI disk" -Percentage 5
Start-Sleep -Milliseconds 1000

$DP1 =
@"
select disk 0
clean
convert gpt
create partition efi size=260
assign letter=R
format quick fs=fat32
"@

RunDP -DP "$DP1" -Log "Created and formated 'efi' partition" -Percentage 25

$DP2 =
@"
select disk 0
create partition msr size=128
"@

RunDP -DP "$DP2" -Log "Created and formated 'msr' partition" -Percentage 40

$DP3 =
@"
select disk 0
create partition primary
format quick fs=ntfs label="Windows"
assign letter=C
shrink desired=984 minimum=984
"@

RunDP -DP "$DP3" -Log "Created and formated 'Windows' partition" -Percentage 80

$DP4 =
@"
select disk 0
create partition primary
format quick fs=ntfs label="Recovery"
set id="de94bba4-06d1-4d40-a16a-bfd50179d6ac"
gpt attributes=0x8000000000000001
"@

RunDP -DP "$DP4" -Log "Created and formated 'Recovery' partition" -Percentage 95
}

$tsenv.Value("OSDisk") = "C:"
WriteLog -LogFileName "$LogFile" -Component "RunPowerShellScript" -FileName "$Self" -LogText "Finished Partition and Format" -Type Info
Show -Action  "Finished Partition and Format" -Percentage 100
Start-Sleep -Milliseconds 400
WriteLog -LogFileName "$LogFile" -Component "RunPowerShellScript" -FileName "$Self" -LogText "Script finished" -Type Info
