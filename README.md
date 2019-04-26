# Forensics
This repository is including Incident Response and Threat hunting scripts


-------------------------------------------
###DFIR_Windows_Server_Triage_PowerShell###
This script will extract triage information that belongs to a specific Windows Server. The following informations are extracted.
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
    Hash of all collected triage data --> MD5 hash of all data collected

This script will create a folder under %TEMP% directory with %HOSTNAME%_TRIAGE_%DATE% format.
The above informations will be created under this folder.

WARNING!!! This script should be run with Administrator rights on the servers.

EXAMPLE usage: ./TriageWindows.ps1


-------------------------------------------
