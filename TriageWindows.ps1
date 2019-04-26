<#
.SYNOPSIS
This script will extract triage information that belongs to a specific Windows Server

.DESCRIPTION
This script will extract triage information that belongs to a specific Windows Server:

    System information --> Build, service pack level, installed patches, etc
    Windows version --> Logs the version number of the target OS
    NetBIOS information --> Active NetBIOS sessions, transferred files, etc
    Current date and time --> Current system date and time
    Eventviewer logs --> including Application, System and Security in last 30 days
    Registry hives --> Copy of all registry hives
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
    Hash of all collected triage data --> SHA1 hash of all data collected

This script will create a folder under %TEMP% directory with %HOSTNAME%_TRIAGE_%DATE% format.
The above informations will be created under this folder.

This script will extract the eventviewer logs in last 30 days, If you need to change this time-range you can edit this script 

.EXAMPLE
./TriageWindows.ps1

.NOTES
    Version:    0.3
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
    [string]$seperator,
    [string]$destinationZip
)
$tempFolderPath = $env:TEMP
Write-Host "Temp folder path is " $env:TEMP
$date = Get-Date -UFormat %d%m%y
Write-Host "Date: "$date
$mainPath = $tempFolderPath+"\"+$env:COMPUTERNAME+"_TRIAGE_"+$date
Write-Host "Main path: "$mainPath
$pathEventViewer = $mainPath + "\EVENTVIEWER"
$pathProcess = $mainPath + "\PROCESS"
$pathNetwork = $mainPath + "\NETWORK"


Function Set-FolderTree()
{
    If(-Not (Test-Path -Path $mainPath)) 
    {
        New-Item -Path $mainPath -ItemType Directory
    }
    If(-Not (Test-Path -Path $pathEventViewer)) 
    {
        New-Item -Path $pathEventViewer -ItemType Directory
    }
    If(-Not (Test-Path -Path $pathProcess)) 
    {
        New-Item -Path $pathProcess -ItemType Directory
    }
    If(-Not (Test-Path -Path $pathNetwork)) 
    {
        New-Item -Path $pathNetwork -ItemType Directory
    }
}

Function Set-FileTree()
{
    If(-Not (Test-Path -Path $mainPath\systemInfo.txt)) 
    {
        New-Item $mainPath\systemInfo.txt
    }
    If(-Not (Test-Path -Path $mainPath\accountInfo.txt)) 
    {
        New-Item $mainPath\accountInfo.txt
    }
    If(-Not (Test-Path -Path $mainPath\filesHash.txt)) 
    {
        New-Item $mainPath\filesHash.txt
    }
    If(-Not (Test-Path -Path $pathProcess\installedApps.txt)) 
    {
        New-Item $pathProcess\installedApps.txt
    }
    If(-Not (Test-Path -Path $pathProcess\runningProcess.txt)) 
    {
        New-Item $pathProcess\runningProcess.txt
    }
    If(-Not (Test-Path -Path $pathProcess\autorun.txt)) 
    {
        New-Item $pathProcess\autorun.txt
    }
    If(-Not (Test-Path -Path $pathProcess\taskSchedule.txt)) 
    {
        New-Item $pathProcess\taskSchedule.txt
    }
    If(-Not (Test-Path -Path $pathProcess\openedFiles.txt)) 
    {
        New-Item $pathProcess\openedFiles.txt
    }
    If(-Not (Test-Path -Path $pathProcess\tempFolder.txt)) 
    {
        New-Item $pathProcess\tempFolder.txt
    }
    If(-Not (Test-Path -Path $pathNetwork\networkInfo.txt)) 
    {
        New-Item $pathNetwork\networkInfo.txt
    }
    If(-Not (Test-Path -Path $pathNetwork\ethernetInfo.txt)) 
    {
        New-Item $pathNetwork\ethernetInfo.txt
    }
    If(-Not (Test-Path -Path $pathNetwork\netConnections.txt)) 
    {
        New-Item $pathNetwork\netConnections.txt
    }
    If(-Not (Test-Path -Path $pathNetwork\tcpUDPConnections.txt)) 
    {
        New-Item $pathNetwork\tcpUDPConnections.txt
    }
    If(-Not (Test-Path -Path $pathNetwork\DNScaches.txt)) 
    {
        New-Item $pathNetwork\DNScaches.txt
    }
    If(-Not (Test-Path -Path $pathNetwork\arpTable.txt)) 
    {
        New-Item $pathNetwork\arpTable.txt
    }
}

Function Get-SystemInfo()
{
    Add-Content $mainPath\systemInfo.txt "----------FULL SYSTEM INFORMATION----------" -Encoding Unicode
    Get-CimInstance Win32_OperatingSystem | FL * | Out-File -FilePath $mainPath\systemInfo.txt -Append
    Add-Content $mainPath\systemInfo.txt $seperator  -Encoding Unicode
    Add-Content $mainPath\systemInfo.txt "----------INSTALLED PATCHES AND HOTFIXES----------" -Encoding Unicode
    Get-WmiObject -Class win32_quickfixengineering | Out-File -FilePath $mainPath\systemInfo.txt -Append
    Add-Content $mainPath\systemInfo.txt $seperator -Encoding Unicode
    Add-Content $mainPath\systemInfo.txt "----------NETBIOS INFORMATION----------" -Encoding Unicode
    Get-SmbSession | Out-File -FilePath $mainPath\systemInfo.txt -Append
}

Function Get-EventviewerLogs()
{
    Add-Content $pathEventViewer\logInfo.txt "----------EVENT LOG LIST AND DETAILS----------" -Encoding Unicode
    Get-EventLog -List | Out-File -FilePath $pathEventViewer\logInfo.txt -Append
    Copy-Item -Path C:\Windows\System32\winevt\Logs\Application.evtx -Destination $pathEventViewer\application.evtx
    Copy-Item -Path C:\Windows\System32\winevt\Logs\System.evtx -Destination $pathEventViewer\system.evtx
    Copy-Item -Path C:\Windows\System32\winevt\Logs\Security.evtx -Destination $pathEventViewer\security.evtx
}

<#
Function Get-Registry()
{
    param 
    (
        [string]$commandReg
    )
    $commandReg = "RegEdit.exe /a "+$mainPath+"\registry.reg"
    cmd.exe /c $commandReg
}
#>


Function Get-AccountInfo()
{
    param
    (
        [string]$currentUser
    )
    Add-Content $mainPath\accountInfo.txt "----------CURRENT USER INFORMATION----------" -Encoding Unicode
    $currentUser = $env:USERDNSDOMAIN + "\" + $env:USERNAME
    $currentUser | Out-File -FilePath $mainPath\accountInfo.txt -Append
    Add-Content $mainPath\accountInfo.txt $seperator -Encoding Unicode
    Add-Content $mainPath\accountInfo.txt "----------LOCAL USER LIST----------" -Encoding Unicode
    Get-LocalUser | Out-File -FilePath $mainPath\accountInfo.txt -Append
    Add-Content $mainPath\accountInfo.txt $seperator -Encoding Unicode
    Add-Content $mainPath\accountInfo.txt "----------LOCAL ADMINISTRATOR USER LIST----------" -Encoding Unicode
    Get-LocalGroupMember -Group "Administrators" | Out-File -FilePath $mainPath\accountInfo.txt -Append
    Add-Content $mainPath\accountInfo.txt $seperator -Encoding Unicode
    Add-Content $mainPath\accountInfo.txt "----------LOGGED ON USER LIST----------" -Encoding Unicode 
    qwinsta | Out-File -FilePath $mainPath\accountInfo.txt -Append
}

Function Get-ProcessServiceApplication()
{
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize > $pathProcess\installedApps.txt
    Get-Process | Format-Table * –AutoSize > $pathProcess\runningProcess.txt
    Add-Content $pathProcess\autorun.txt $seperator -Encoding Unicode
    Add-Content $pathProcess\autorun.txt "----------LIST OF AUTORUN APPLICATIONS----------" -Encoding Unicode     
    Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-Table * –AutoSize | Out-File -FilePath $pathProcess\autorun.txt -Append
    Add-Content $pathProcess\autorun.txt $seperator -Encoding Unicode
    Add-Content $pathProcess\autorun.txt "----------LIST OF SERVICES----------" -Encoding Unicode     
    Get-Service | Format-Table * -AutoSize | Out-File -FilePath $pathProcess\autorun.txt -Append    
    Get-ScheduledTask | Format-Table * -AutoSize | Out-File -FilePath $pathProcess\taskSchedule.txt
    Get-SMBOpenFile | Select-Object -Property * | Out-File -FilePath $pathProcess\openedFiles.txt
    Get-ChildItem -Path $tempFolderPath | Out-File -FilePath $pathProcess\tempFolder.txt
}

Function Get-NetworkInfo()
{
    Add-Content $pathNetwork\networkInfo.txt $seperator -Encoding Unicode
    Add-Content $pathNetwork\networkInfo.txt "----------IP CONFIGURATION----------" -Encoding Unicode 
    Get-NetIPAddress | Select-Object -Property PrefixOrigin, InterfaceAlias, AddressFamily, IPv4Address, AddressState | Format-Table * -AutoSize | Out-File -FilePath $pathNetwork\networkInfo.txt -Append
    Add-Content $pathNetwork\networkInfo.txt $seperator -Encoding Unicode
    Add-Content $pathNetwork\networkInfo.txt "----------CONNECTION PROFILE----------" -Encoding Unicode 
    Get-NetConnectionProfile | Out-File -FilePath $pathNetwork\networkInfo.txt -Append
    Add-Content $pathNetwork\networkInfo.txt $seperator -Encoding Unicode
    Add-Content $pathNetwork\networkInfo.txt "----------ROUTING CONFIGURATION----------" -Encoding Unicode 
    Get-NetRoute | Format-Table * -AutoSize | Out-File -FilePath $pathNetwork\networkInfo.txt -Append
    Get-NetAdapter | Format-Table * -AutoSize | Out-File -FilePath $pathNetwork\ethernetInfo.txt
    Get-NetTCPConnection | Out-File -FilePath $pathNetwork\netConnections.txt
    cmd.exe /C "netstat -nao" | Out-File -FilePath $pathNetwork\tcpUDPConnections.txt
    Get-DnsClientCache | Out-File -FilePath $pathNetwork\DNScaches.txt
    Get-NetNeighbor | Out-File -FilePath $pathNetwork\arpTable.txt
}

Function Get-FileHashes()
{
    param
    (
        [String[]]$files
    ) 
    $files = "$pathEventViewer\application.evtx", "$pathEventViewer\security.evtx", "$pathEventViewer\system.evtx", "$mainPath\systemInfo.txt", "$mainPath\accountInfo.txt", "$pathProcess\installedApps.txt", "$pathProcess\runningProcess.txt", "$pathProcess\autorun.txt", "$pathProcess\taskSchedule.txt", "$pathProcess\openedFiles.txt", "$pathProcess\tempFolder.txt", "$pathNetwork\networkInfo.txt", "$pathNetwork\ethernetInfo.txt", "$pathNetwork\netConnections.txt", "$pathNetwork\tcpUDPConnections.txt", "$pathNetwork\DNScaches.txt", "$pathNetwork\arpTable.txt"
    
    ForEach ($file in $files)
    {
        Get-FileHash $file -Algorithm SHA1 | Format-Table -AutoSize -HideTableHeaders | Out-File -FilePath $mainPath\filesHash.txt -Append
    }
}

#Main Functions
Set-FolderTree
Set-FileTree
Get-SystemInfo
Get-EventviewerLogs
#Get-Registry
Get-AccountInfo
Get-ProcessServiceApplication
Get-NetworkInfo
Get-FileHashes
$destinationZip = $mainPath + ".zip"
Compress-Archive -Path $mainPath -CompressionLevel Optimal -DestinationPath $destinationZip 
