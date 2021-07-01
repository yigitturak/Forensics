<#
.SYNOPSIS
This script will extract triage information that belongs to a specific Windows Server regarding to CVE-2021-1675 (PrintNightmare) vulnerability

.DESCRIPTION
    System information --> Build, service pack level, installed patches, etc
    Windows version --> Logs the version number of the target OS
    NetBIOS information --> Active NetBIOS sessions, transferred files, etc
    Current date and time --> Current system date and time
    Eventviewer logs --> including Application, System, Security, powershell, PrintService/Admin and SMBClient/Security. By default it is getting the last 15 days logs. If you change it, play with the parameter $daysBefore
    Registry hives --> Copy of all registry hives - HKLM\SYSTEM\CurrentControlSet
    Current user information --> User running this script
    Local user account names --> List of local user accounts
    Local administrators --> List of local admin right users
    Logged on users --> All users currently logged on to target system
    Installed software --> List of all installed software through WMI
    Loaded processes and dlls --> List of all running processes and loaded dlls
    Autorun applications/services --> List of autorun applications and services
    List of scheduled tasks --> List of all configured scheduled tasks
    List of remotely opened files --> Files on target system opened by remote hosts
    List of %TEMP% folder files --> Files in %TEMP% folder
    Network information --> Network configuration, routing tables, etc
    Network configuration --> Network adaptor configuration
    Network connections --> Established network connections           
    Open TCP/UDP ports --> Active open TCP or UDP ports                    
    DNS cache entries --> List of complete DNS cache contents           
    ARP table information --> List of complete ARP cache contents
    Antivirus logs --> All logs of Mcafee or Microsoft AV
    Hash of all collected triage data --> MD5 hash of all data collected

This script will create a folder under %TEMP% directory with %HOSTNAME%_TRIAGE_%DATE% format.
The above informations will be created under this folder.

This script should be run by administrator right on the system.

.EXAMPLE
./Triage_v1.1-PrintNightmare.ps1

.NOTES
    Version:    1.1
    Author:     Yigit Turak
#>

param
(
    [string]$tempFolderPath,
    [string]$date,
    [string]$mainPath,
    [string]$pathEventViewer,
    [string]$pathProcess,
    [string]$pathNetwork,
    [string[]]$pathAll,
    [string[]]$fileAll,
    [string]$destinationZip
)

$tempFolderPath = $env:TEMP
$date = Get-Date -UFormat %d%m%y
$foldername = $env:COMPUTERNAME+"_TRIAGE_"+ $date
$mainPath = $tempFolderPath+"\" + $foldername
$pathEventViewer = $mainPath + "\EVENTVIEWER"
$pathProcess = $mainPath + "\PROCESS"
$pathNetwork = $mainPath + "\NETWORK"
$pathAll = "$mainPath", "$pathEventViewer", "$pathProcess", "$pathNetwork"
$fileAll = "$mainPath\filelist_Spool_folder.json", "$mainpath\reg_value_NoWarningNoElevationOnInstall.txt", "$mainpath\accountInfo.txt", "$mainpath\filesHash.json", "$mainpath\installedPatches.json", "$mainpath\localadmin-users.json", "$mainpath\netbios-info.json", "$mainpath\systemInfo.json", "$pathNetwork\arpTable.json", "$pathNetwork\connectionProfile.json", "$pathNetwork\DNScaches.json", "$pathNetwork\ethernetInfo.json", "$pathNetwork\netConnections.json", "$pathNetwork\networkInfo.json", "$pathNetwork\routing.json", "$pathNetwork\tcpUDPConnections.txt", "$pathProcess\autorun.json", "$pathProcess\installedApps.json", "$pathProcess\installedApps_Fulldetailed.json", "$pathProcess\openedFiles.json", "$pathProcess\runningProcess.json", "$pathProcess\services.json", "$pathProcess\taskSchedule.json", "$pathProcess\tempFolder_user.json", "$pathProcess\tempFolder_windir.json"
$destinationZip = $mainPath + ".zip"
$logDateToday = Get-Date
$daysBefore = 30
$logDateBefore = $logDateToday.AddDays(-$daysBefore)

Function Set-FolderTree()
{
    ForEach ($path in $pathAll)
    {
        If(-Not (Test-Path -Path $path)) 
        {
            New-Item -Path $path -ItemType Directory
        }
    }
}

Function Set-FileTree()
{
    ForEach ($file in $fileAll)
    {
        If(-Not (Test-Path -Path $file)) 
        {
            New-Item $file
        }   
    }
}

#This function gets system, netbios and patch information
Function Get-SystemInfo()
{
    Add-Content $mainPath\systemInfo.json "[" -Encoding Unicode 
    Get-CimInstance Win32_OperatingSystem | Select-Object -Property FreePhysicalMemory,FreeSpaceInPagingFiles,FreeVirtualMemory,Caption,InstallDate,CSName,CurrentTimeZone,LastBootUpTime,LocalDateTime,NumberOfUsers,Version,Organization,OSArchitecture,BootDevice,SystemDevice,SystemDirectory,SystemDrive | ConvertTo-JSON | Out-File -FilePath $mainPath\systemInfo.json -Append
    Add-Content $mainPath\systemInfo.json "]" -Encoding Unicode
    Get-WmiObject -Class win32_quickfixengineering | Select-Object -Property Description,HotFixID,InstalledBy,InstalledOn | Sort-Object InstalledOn | ConvertTo-JSON | Out-File -FilePath $mainPath\installedPatches.json
    Get-SmbSession | ConvertTo-Json | Out-File -FilePath $mainPath\netbios-info.json
}

#This function copies app,sys and sec event logs to our folder
Function Get-EventviewerLogs()
{
    Set-Variable -Name LogNames -Value @("Windows Powershell", "Security", "Application", "System")
    Set-Variable -Name EventTypes -Value @("Error", "Warning", "Information", "FailureAudit", "SuccessAudit")

    foreach($log in $LogNames)
    {
        Write-Host Processing $log
        $ExportFile = $pathEventViewer + "\" + $log + ".csv"
        Get-Eventlog -log $log -After $logDateBefore -EntryType $EventTypes | Export-CSV $ExportFile -NoTypeInfo  #EXPORT
    }
}

#This function extracts the regestry values under HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet
Function Get-Registry()
{
    reg export HKLM\SYSTEM\CurrentControlSet $mainpath\registry.reg
}

#This function gathers the account information like current user, local user list, local admin accounts and logged on user list
Function Get-AccountInfo()
{
    param
    (
        [string]$currentUser
    )
    Add-Content $mainPath\accountInfo.txt "----------CURRENT USER INFORMATION----------" -Encoding Unicode
    $currentUser = $env:USERDNSDOMAIN + "\" + $ENV:USERNAME
    $currentUser | Out-File -FilePath $mainPath\accountInfo.txt -Append
    
    Get-LocalUser | ConvertTo-Json | Out-File -FilePath $mainPath\local-accounts.json
    Get-LocalGroupMember -Group "Administrators" | ConvertTo-Json | Out-File -FilePath $mainPath\localadmin-users.json
    
    Add-Content $mainPath\accountInfo.txt "----------LOGGED ON USER LIST----------" -Encoding Unicode 
    qwinsta | Out-File -FilePath $mainPath\accountInfo.txt -Append
}

#This function extracts running processes, autorun apps, scheduled tasks, SMB open files, files under temp folder and list of services
Function Get-ProcessServiceApplication()
{
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | ConvertTo-Json | Out-File -FilePath $pathProcess\installedApps.json
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object -Property * | ConvertTo-Json | Out-File -FilePath $pathProcess\installedApps_Fulldetailed.json

    $ProcExes = Get-WmiObject -Namespace root\cimv2 -Class CIM_ProcessExecutable 
    $x = foreach ($item in $ProcExes) 
    {
    [wmi]"$($item.Antecedent)" | Select-Object Name,Filename,Extension,Manufacturer,Version -Unique
    } 
    $x | Sort-Object filename | Get-Unique -AsString| ConvertTo-Json |  Out-File -FilePath $pathProcess\runningProcess.json -Force

    Get-CimInstance Win32_StartupCommand | Select-Object Name, command, User | ConvertTo-Json | Out-File -FilePath $pathProcess\autorun.json
    Get-Service | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json | Out-File -FilePath $pathProcess\services.json
    Get-ScheduledTask | Select-Object -Property * |  ConvertTo-Json |Out-File -FilePath $pathProcess\taskSchedule.json
    Get-SMBOpenFile | Select-Object -Property * |  ConvertTo-Json |Out-File -FilePath $pathProcess\openedFiles.json
    Get-ChildItem -Path $tempFolderPath -Exclude $foldername | Get-ChildItem -Recurse | Select-Object -Property FullName, BaseName, Name, Parent, Root, Extension, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc| ConvertTo-Json | Out-File -FilePath $pathProcess\tempFolder_user.json
    Get-ChildItem -Path $env:windir\temp -Recurse | Select-Object -Property FullName, BaseName, Name, Parent, Root, Extension, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc| ConvertTo-Json | Out-File -FilePath $pathProcess\tempFolder_windir.json
}

#This function extracts the network information like IP, routings, connections, DNS cache and ARP table
Function Get-NetworkInfo()
{
    Get-NetIPAddress | Select-Object -Property PrefixOrigin, InterfaceAlias, AddressFamily, IPv4Address, AddressState |  ConvertTo-Json | Out-File -FilePath $pathNetwork\networkInfo.json
    
    Get-NetConnectionProfile |  ConvertTo-Json | Out-File -FilePath $pathNetwork\connectionProfile.json
    
    Get-NetRoute |  ConvertTo-Json | Out-File -FilePath $pathNetwork\routing.json
    
    Get-NetAdapter | ConvertTo-Json | Out-File -FilePath $pathNetwork\ethernetInfo.json
    Get-NetTCPConnection |  ConvertTo-Json | Out-File -FilePath $pathNetwork\netConnections.json
    cmd.exe /C "netstat -nao" | Out-File -FilePath $pathNetwork\tcpUDPConnections.txt
    Get-DnsClientCache |  ConvertTo-Json | Out-File -FilePath $pathNetwork\DNScaches.json
    Get-NetNeighbor |  ConvertTo-Json | Out-File -FilePath $pathNetwork\arpTable.json
}

Function Get-AVLogs()
{
    param()
    {
        [string]$mcafeeLogs
        [string]$mcafeeLogsPath
        [string]$msAVLogs
        [string]$msAVLogsPath
    }
    $mcafeeLogs = "C:\ProgramData\McAfee\Endpoint Security\Logs"
    $mcafeeLogsPath = $mainPath + "\logs"
    
    If(Test-Path -Path $mcafeeLogs)
    {
        Copy-Item -Path $mcafeeLogs -Recurse -Destination $mainPath
        Rename-Item -Path $mcafeeLogsPath -NewName "McAfeeLogs"
    }
    
    $msAVLogs = "C:\ProgramData\Microsoft\Microsoft Antimalware\Support"
    $msAVLogsPath = $mainPath + "\support"
    If(Test-Path -Path $msAVLogs)
    {
        Copy-Item -Path $msAVLogs -Recurse -Destination $mainPath
        Rename-Item -Path $msAVLogsPath -NewName "MSAntivirusLogs"
    }
}

Function Get-CVE-2021-1675_IOCs(){

    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\Printers\PointAndPrint\NoWarningNoElevationOnInstall" | Out-File -FilePath $mainPath\reg_value_NoWarningNoElevationOnInstall.txt
 
    Copy-Item -Path $env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-PrintService%4Admin.evtx -Destination $pathEventViewer
    Copy-Item -Path $env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-SmbClient%4Security.evtx -Destination $pathEventViewer
    Get-ChildItem -Path $env:SystemRoot\System32\spool\drivers\x64 -Recurse | Select-Object -Property FullName, BaseName, Name, Parent, Root, Extension, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc| ConvertTo-Json | Out-File -FilePath $mainPath\filelist_Spool_folder.json
}



#This is a forensics required function that calculates the SHA1 hash of each file.
Function Get-FileHashes()
{
    param
    (
        [String[]]$files
    ) 
    $files =  Get-ChildItem -Path $mainPath -Include *.txt,*.json,*.csv,*.log, *.reg -Recurse | Select-Object -Property FullName

    Write-Output "[" | Out-File -FilePath $mainpath\filesHash.json -Append
    ForEach ($file in $files)
    {
        If(Test-Path -Path $file)
        {
            If($file -ne "$pathProcess\tempFolder_windir.json"){
                Get-FileHash $file -Algorithm SHA1 | ConvertTo-Json | Out-File -FilePath $mainPath\filesHash.json -Append
                Write-Output "," | Out-File -FilePath $mainpath\filesHash.json -Append
            }
            else {
                Get-FileHash $file -Algorithm SHA1 | ConvertTo-Json | Out-File -FilePath $mainPath\filesHash.json -Append
            }
        }
        
    }
    Write-Output "]" | Out-File -FilePath $mainpath\filesHash.json -Append
}


###############################################################
####################--Main Functions--#########################
###############################################################
Write-Host "Today: " + $logDateToday + "\nBefore: " + $logDateBefore
Set-FolderTree
Write-Host "Folder are created"
Set-FileTree
Write-Host "Files are created"
Write-Host "Extracting system info"
Get-SystemInfo
Write-Host "Extracting event logs"
Get-EventviewerLogs
Write-Host "Extracting registry"
Get-Registry
Write-Host "Extracting account info"
Get-AccountInfo
Write-Host "Extracting process"
Get-ProcessServiceApplication
Write-Host "Extracting network info"
Get-NetworkInfo
Write-Host "Extracting AV Logs"
Get-AVLogs
Get-CVE-2021-1675_IOCs
Write-Host "Extracting AV Logs"
Get-FileHashes
Write-Host "calculated hashes"
Compress-Archive -Path $mainPath -CompressionLevel Optimal -DestinationPath $destinationZip
Write-Host "Folder is compressed"
Write-Host "-------END------"