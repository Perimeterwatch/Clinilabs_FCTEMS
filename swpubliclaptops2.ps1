#
# Copyright (c) 2024 SecureWorks, Corp. All Rights Reserved.
#
# Module: Taegis agent replacing Red Cloak
#
# Original Author: David Persky
#
# Version: 2.4
# 
# Disclaimer:
# This script, when executed, will remove your Red Cloak Agent (if present), and install the Taegis Agent. We recommend you trial this script first on a few Windows systems, and deploy in limited batches.
#
# Abstract:

# THIS SCRIPT MUST BE RUN AS ADMINISTRATOR
# 1) No reboots or end-user interaction (desktop pop ups or approvals) occur during the execution of this script.
# 2) Script execution policy should be set to 'unrestricted' or 'bypass' before executing the script - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.3
#"Set-ExecutionPolicy -ExecutionPolicy Unrestricted" - and then revert to your desired setting after completion.
# 3) Customer must customize "<path>.msi", 'REGISTRATIONKEY=<registration key>', 'REGISTRATIONSERVER=<registration server>', 'PROXY=<proxyserver:port>', 'DNS=<host>' in params section just below
# 4) Proxy customization is optional however supplying a DNS server is required if supplying a proxy IP. 
# 5) *IMPORTANT* Please use latest version of Taegis agent package in your XDR endpoint downloads page for successful execution.
# 6) AgentMigrator script results will output to C:\ProgramData\SecureWorks\Taegis_Agent_Install_Log.txt, which you can access after script execution to observe the result.  A successful install will include the line "AgentMigrator script completed successfully!", which you can parse for.

#Removes temp AgentMigrator transcription file if it already exists
if (Test-Path "C:\ProgramData\SecureWorks\Taegis_Agent_Install_Log.txt") {
    Remove-Item "C:\ProgramData\SecureWorks\Taegis_Agent_Install_Log.txt" -Force
}

#Set and begins powershell transcription of output:
$transcriptPath = "C:\ProgramData\SecureWorks\Taegis_Agent_Install_Log.txt"
$null = Start-Transcript -Path $transcriptPath

#Append nicely formatted messaging to beginning of transcription file:
Write-Output "=================================================
=====BEGIN AGENT MIGRATOR SCRIPT OUTPUT LOGS=====
================================================="

Write-output "Version 2.4:"

################## BEGIN FUNCTIONS SECTION ##################
#Function to be run later which stops powershell transcriptions and appends end of logs nicely formatted messaging:
function Stop-Transcript-and-log {
    # Stop the transcript logging
    Stop-Transcript

    # Add lines of text to the end of the transcript file
    $textToAdd = @"
========================================
=====END AGENT MIGRATOR OUTPUT LOGS=====
========================================
"@

    # Append text to the transcript file
    Add-Content -Path C:\ProgramData\SecureWorks\Taegis_Agent_Install_Log.txt -Value $textToAdd
}

#Function to be run later which checks if the system's group policy has automatic certificate authorities list updating:
function Auto-CA-update-check {
# Define the registry path where the policy setting is stored
$regPath = "HKLM:\Software\Policies\Microsoft\SystemCertificates\AuthRoot"

# Define the registry value that controls the "Turn off automatic root certificates update" policy
$regValueName = "DisableRootAutoUpdate"

# Check if the registry path exists
if (Test-Path $regPath) {
    # Retrieve the value of the registry key
    $regValue = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue

    if ($regValue) {
        # Check if the policy is enabled (1 means the policy is enabled)
        if ($regValue.$regValueName -eq 1) {
            Write-Output "'Turn off automatic root certificates update' is enabled in the group policy.  We recommend disabling it so that certificate authorities can update."
        } else {
            Write-Output "'Turn off automatic root certificates update' is disabled in the group policy so the certificate authority list should be updating."
        }
    } else {
        Write-Output "'Turn off automatic root certificates update' is not configured so the certificate authority list should be updating."
    }
} else {
    Write-Output "'Turn off automatic root certificates update' is not configured so the certificate authority list should be updating."
}
}
################## END FUNCTIONS SECTION ##################

# Check if the script is run with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "ERROR: This script requires administrative privileges. Please run it as an administrator.`n"
    Stop-Transcript-and-log
    exit 1
}

#Creates Secureworks directory if nonexistant:
$directory = "C:\ProgramData\SecureWorks"
if (-not (Test-Path $directory)) {
    New-Item -ItemType Directory -Path $directory
}

# Define the credentials (replace with your actual username and password)
$username = "Clinilabs-DC\dcdmastr"
$password = ConvertTo-SecureString "GnZa2b3sQ!" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($username, $password)

# Parameter definitions for msiexec:
# REQUIRED FIELDS:
#============================================================================
$logfile = "C:\ProgramData\SecureWorks\TEMP_Taegis_Agent_Install_Log.txt"
$REGISTRATIONSERVER = "REGISTRATIONSERVER=reg.d.taegiscloud.com"
$REGISTRATIONKEY = "REGISTRATIONKEY=MTQ4NjMzfE0yQnM2cWR3blZLM0dBYjBMSTdCTmt5"
$msiUrl = "https://github.com/Perimeterwatch/westmonroe/blob/main/taegis-agent_en_2.2.12_x64.msi?raw=true"
$msiPath = "C:\taegis-agent_en_2.2.12_x64.msi"
$DNS = "DNS=8.8.8.8"
#============================================================================
# OPTIONAL FIELDS:
#============================================================================
# When Taegis Agent needs to communicate via your internal proxy server, uncomment the below to use $Proxy:
# $Proxy = "PROXY=1.2.3.4:8080"
#============================================================================

# Download the MSI file
Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath

# Define the parameters for msiexec
$params = "/i $msiPath /qn /l*v $logfile $REGISTRATIONSERVER $REGISTRATIONKEY $DNS"

# Run the MSI installer
Start-Process msiexec.exe -ArgumentList $params -Wait

Write-Output "Installation complete. Log file: $logfile" 

##### OPTIONAL PROXY #####
#If you have defined a proxy server in the optional field above, please remove the "#" symbol before $Proxy on the 
#following line to ensure correct installation parameters.
$MSI_path, $REGISTRATIONKEY, $REGISTRATIONSERVER, $DNS, '/norestart', '/l*vx', $logfile, '/quiet'#, $Proxy

#Pre-install OS Verification check.  Supported versions are:
#Windows 10
#Windows 11
#Windows Server 2016
#Windows Server 2019
#Windows Server 2022
#Script won't execute on older Windows OSs

Write-Output "***Pre-install checks output***`n"
$allowedVersions = @("10", "11", "2016", "2019", "2022")

$osVersion = (Get-CimInstance -Class Win32_OperatingSystem).Version
$osMajorVersion = [System.Version]::Parse($osVersion).Major

if ($allowedVersions -contains $osMajorVersion) {

    Write-Output "1) PASS: Operating system version is supported. Initiating pre-install connectivity checks...`n"
    } else {

#Pre-install OS Verification error handling
    Write-Output "1) ERROR: Operating system version is not supported. Taegis agent install halted.  Red Cloak uninstall halted.  Please verify supported operating systems`n
    https://docs.ctpx.secureworks.com/taegis_agent/supported_os/."
    $null = Stop-Transcript-and-log
    exit 1
}

#Validating if MS Defender is running and if so, add Taegis agent exclusions for it:
$service = Get-Service -Name WinDefend

if ($service.Status -eq 'Running') {
    Write-Output "`n2) INFORMATIONAL: Microsoft Defender is running, adding the following Taegis agent directories to exclusion list:`n 
    C:\Program Files\SecureWorks\
    C:\ProgramData\SecureWorks\`n"

    Add-MpPreference -ExclusionPath 'C:\Program Files\SecureWorks\'
    Add-MpPreference -ExclusionPath 'C:\ProgramData\SecureWorks\'

} else {
    $antivirus = Get-CimInstance -Namespace "root\SecurityCenter2" -Class AntiVirusProduct

if ($antivirus) {
    Write-Output "`n2) INFORMATIONAL: Antivirus Product Name: $($antivirus.displayName).  Please add the following directories to your exclusions list within your anti-virus:
    C:\Program Files\SecureWorks\`n
    C:\ProgramData\SecureWorks\`n"

} else {
    Write-Output "`n2) INFORMATIONAL: No antivirus product found or the information is not accessible."
}
}

# Parse $REGISTRATIONSERVER and determine which test connections to perform
switch -Wildcard ($REGISTRATIONSERVER) {
    "*reg.c.taegiscloud.com" {
        Write-Output "`n3) Performing 'C' environment test connections..."
        # Define test connections for Cport
        $Port443 = (Test-NetConnection -ComputerName reg.c.taegiscloud.com -Port 443).TcpTestSucceeded
        $PortT443 = (Test-NetConnection -ComputerName telemetry.c.taegiscloud.com -Port 443).TcpTestSucceeded
        $Port8443 = (Test-NetConnection -ComputerName sink.c.taegiscloud.com -Port 8443).TcpTestSucceeded
        $Port443S3 = (Test-NetConnection -ComputerName file-receiver-c.s3.us-east-2.amazonaws.com -Port 443).TcpTestSucceeded
        $Port9443 = (Test-NetConnection -ComputerName file-receiver.c.taegiscloud.com -Port 9443).TcpTestSucceeded
    }
    "*reg.d.taegiscloud.com" {
        Write-Output "`n3) Performing 'D' environment test connections..."
        # Define test connections for Dport
        $Port443 = (Test-NetConnection -ComputerName reg.d.taegiscloud.com -Port 443).TcpTestSucceeded
        $PortT443 = (Test-NetConnection -ComputerName telemetry.d.taegiscloud.com -Port 443).TcpTestSucceeded
        $Port8443 = (Test-NetConnection -ComputerName sink.d.taegiscloud.com -Port 8443).TcpTestSucceeded
        $Port443S3 = (Test-NetConnection -ComputerName file-receiver-d.s3.us-east-2.amazonaws.com -Port 443).TcpTestSucceeded
        $Port9443 = (Test-NetConnection -ComputerName file-receiver.d.taegiscloud.com -Port 9443).TcpTestSucceeded
    }
    "*reg.e.taegiscloud.com" {
        Write-Output "`n3) Performing 'E' environment test connections..."
        # Define test connections for Eport
        $Port443 = (Test-NetConnection -ComputerName reg.e.taegiscloud.com -Port 443).TcpTestSucceeded
        $PortT443 = (Test-NetConnection -ComputerName telemetry.e.taegiscloud.com -Port 443).TcpTestSucceeded
        $Port8443 = (Test-NetConnection -ComputerName sink.e.taegiscloud.com -Port 8443).TcpTestSucceeded
        $Port443S3 = (Test-NetConnection -ComputerName file-receiver-e.s3.us-east-2.amazonaws.com -Port 443).TcpTestSucceeded
        $Port9443 = (Test-NetConnection -ComputerName file-receiver.e.taegiscloud.com -Port 9443).TcpTestSucceeded
    }
    "*reg.f.taegiscloud.com" {
        Write-Output "`n3) Performing 'F' environment test connections..."
        # Define test connections for Fport
        $Port443 = (Test-NetConnection -ComputerName reg.f.taegiscloud.com -Port 443).TcpTestSucceeded
        $PortT443 = (Test-NetConnection -ComputerName telemetry.f.taegiscloud.com -Port 443).TcpTestSucceeded
        $Port8443 = (Test-NetConnection -ComputerName sink.f.taegiscloud.com -Port 8443).TcpTestSucceeded
        $Port443S3 = (Test-NetConnection -ComputerName file-receiver-f.s3.us-east-2.amazonaws.com -Port 443).TcpTestSucceeded
        $Port9443 = (Test-NetConnection -ComputerName file-receiver.f.taegiscloud.com -Port 9443).TcpTestSucceeded
    }
}

# Perform the common test connections
$Agent_Update443 = (Test-NetConnection -ComputerName taegis-agent-prod-builds.s3.us-east-2.amazonaws.com -Port 443).TcpTestSucceeded
$crl80 = (Test-NetConnection -ComputerName crl.rootca1.amazontrust.com -Port 80).TcpTestSucceeded
$crl380 = (Test-NetConnection -ComputerName crl3.digicert.com -Port 80).TcpTestSucceeded
$crl480 = (Test-NetConnection -ComputerName crl4.digicert.com -Port 80).TcpTestSucceeded
$oscp80 = (Test-NetConnection -ComputerName ocsp.digicert.com -Port 80).TcpTestSucceeded
$MS80 = (Test-NetConnection -ComputerName www.microsoft.com -Port 80).TcpTestSucceeded
$crl_MS80 = (Test-NetConnection -ComputerName crl.microsoft.com -Port 80).TcpTestSucceeded

# Check if all connections are successful
if (($Port443 -and $PortT443 -and $Port8443 -and $Port443S3 -and $Port9443) -and
   ($Agent_Update443 -and $crl80 -and $crl380 -and $crl480 -and $oscp80 -and $MS80 -and $crl_MS80)) {
    Write-Output "PASS: Connection checks passed successfully, proceeding with next validation check...`n"
} else {
    # Connection check error handling
    Write-Output "`nERROR: Connection checks failed. Taegis installation and Red Cloak uninstallation skipped. Please implement network connectivity requirements - https://docs.ctpx.secureworks.com/taegis_agent/install/#network-connectivity-requirements."
    $null = Stop-Transcript-and-log
    exit 1
}

#Pre-install Certificate checks:
#The following is required to establish TLS connection to sink.<env>.taegiscloud.com
if  (((get-childitem -path cert:\LocalMachine\AuthRoot | Select-String "ISRG").count -eq 1) -or
    (get-childitem -path cert:\LocalMachine\Root | Select-String "ISRG").count -eq 1)

{ 
    Write-Output "`n4) PASS: Validated presence of ISRG root X1 certificate authority required for websocket connection.  Proceeding with next validation check...`n" 

} else {
#Pre-install Certificate check error handling
    Write-Output "`n4) INFORMATIONAL: 'ISRG root X1' is missing from the trusted root CA store on this system.  This may be added during the install about to occur."
}
if  (((get-childitem -path cert:\LocalMachine\AuthRoot | Select-String "Starfield").count -eq 1) -or
    (get-childitem -path cert:\LocalMachine\Root | Select-String "Starfield").count -eq 1)

{ 
    Write-Output "`n5) PASS: Validated presence of 'Starfield Services Root Certificate Authority' certificate authority required for connection.  Proceeding with next validation check...`n" 

} else {
#Pre-install Certificate check error handling
    Write-Output "`n5) INFORMATIONAL: 'Starfield Services Root Certificate Authority' is missing from the trusted root CA store on this system.  This may be added during the install about to occur.`n"
}

# Verify if any of the variables are undefined, and skip installation:

if (-not (Test-Path $MSI_path -PathType Leaf)) {
    Write-Output "`n6) Error: The MSI file does not exist at $MSI_path."
    $null = Stop-Transcript-and-log
    exit 1
}

$errorMsg = "6) ERROR: Check your input values and customize the script again."

if ($REGISTRATIONKEY -eq "REGISTRATIONKEY=<registration key>" -or $REGISTRATIONKEY -notlike "REGISTRATIONKEY=*") {
    Write-Output "`n$errorMsg Variable: REGISTRATIONKEY.  The format should be REGISTRATIONKEY=<YourRegKey>."
    $null = Stop-Transcript-and-log
    exit 1
}

if ($REGISTRATIONSERVER -eq "REGISTRATIONSERVER=<registration server>" -or $REGISTRATIONSERVER -notlike "REGISTRATIONSERVER=*") {
    Write-Output "`n$errorMsg Variable: REGISTRATIONSERVER.  The format should be REGISTRATIONSERVER=<YourRegServer>."
    $null = Stop-Transcript-and-log
    exit 1
}

if ($DNS -eq "DNS=<host>" -or $DNS -notlike "DNS=*") {
    Write-Output "`n$errorMsg DNS is not properly defined. The format should be DNS=IP1;IP2"
    $null = Stop-Transcript-and-log
    exit 1
}

Write-Output "`nDNS Validation testing:`n"
# DNS over HTTPS endpoint
$doHUri = "https://8.8.8.8/resolve?name=reg.c.taegiscloud.com&type=a&do=1"

$doHTestFailed = $false

# Save the current $ErrorActionPreference
$prevErrorActionPreference = $ErrorActionPreference

# Set $ErrorActionPreference to SilentlyContinue
$ErrorActionPreference = 'SilentlyContinue'

$response = Invoke-WebRequest -Uri $doHUri -Method Get
$response_UseBasicParsing = Invoke-WebRequest -Uri $doHUri -Method Get -UseBasicParsing

# Restore the previous $ErrorActionPreference
$ErrorActionPreference = $prevErrorActionPreference

if (($response.StatusCode -eq 200) -or ($response_UseBasicParsing.StatusCode -eq 200)) {
    Write-Output "`n6) DNS over HTTPS test successful. Testing of customer supplied DNS IPs only performed if DoH is unreachable.`n"
} else {
    Write-Output "6) INFORMATIONAL: Unable to perform DNS over HTTPS (DOH) resolution using Google DNS server 8.8.8.8. Proceeding to test customer supplied DNS IPs:`n"
    $doHTestFailed = $true
}

if ($doHTestFailed) {
    if ($DNS -ne "DNS=<host>") {

# Parse IP addresses from $DNS variable
$ipAddresses = ($DNS -replace '^DNS=') -split ';'

# Regular expression pattern for validating IP addresses
$ipPattern = '^\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b$'

#Set DNS validation variable to false now, later set to true if DNS resolution is successful
$DNSIPVALIDATION = $false

# Iterate through each IP address
foreach ($ip in $ipAddresses) {
    # Validate IP address format using regex
    if ($ip -notmatch $ipPattern) {
        Write-Error "Malformed IP address: $ip"
        continue
    }

    # Perform DNS resolution check
    try {
        $dnsResolution = Resolve-DnsName -Server $ip -Name "reg.c.taegiscloud.com" -ErrorAction Stop | Select-Object -First 1
        if ($dnsResolution) {
            # Parse out the resolved IP address
            $ResolvedIP = $dnsResolution.IPAddress
            if ($ResolvedIP -ne $null) {
                Write-Output "7) PASS: DNS resolution successful using DNS server $ip.`n"
                $DNSIPVALIDATION = $true
                break
            }
        }
    } catch {
        $errorMessage = $_.Exception.Message
        if ($errorMessage -match "timeout period expired") {
            Write-Output "7) WARNING: DNS server $ip is unreachable. Please check the server or network configuration.`n"
        }
    }
}

if ($DNSIPVALIDATION -eq $false) {
    Write-Output "7) ERROR: All customer supplied DNS IP addresses unreachable.  Please check the server or network configuration.`n"
    $null = Stop-Transcript-and-log
    exit 1
}
}
}
 
if ($MSI_path -eq "<path>.msi") {
   Write-Output "7) ERROR: $MSI_path is undefined, please customize and execute script again."
   $null = Stop-Transcript-and-log
   exit 1
} 

Write-Output "`n7) Taegis Agent install in progress. Note there is a 3 minute delay before Red Cloak is uninstalled. Results will be presented to you shortly...`n"

Write-Output "`n=================================
====BEGIN MSIEXEC INSTALL LOG====
================================="

#Stop Transcript before msiexec installation begins:
$null = Stop-Transcript

#Msiexec performs install with parameters above:
msiexec.exe @params

#3 min pause for install to complete and services to begin before RC uninstall
Start-Sleep -Seconds 180

#Redirects unicode encoded temp msiexec log file output into transcript log file (deletion of temp file performed at end of script)
Get-Content -Path $logfile -Encoding Unicode | Out-File -FilePath $transcriptPath -Encoding UTF8 -Append

#Resume transcript to log file C:\ProgramData\SecureWorks\AgentMigrator_log.txt
$null = Start-Transcript -Path $transcriptPath -Append

Write-Output "`n=================================
=====END MSIEXEC INSTALL LOG=====
================================="

#Post-install Taegis agent verification checks
#Verifies successful Taegis agent install, processes running, and established connection before beginning Red Cloak uninstall:
if ((Get-CimInstance -Class Win32_Product -Filter "Name='Taegis Agent'" | Select-String "IdentifyingNumber").Count -ne 1) {
    Write-Output "`nInstallation validation error: Taegis agent is not installed.  Please troubleshoot and repeat installation attempt.  Please open a Taegis XDR chat, ticket, or call Secureworks and provide us the C:\ProgramData\SecureWorks\Taegis_Agent_Install_Log file for analysis."

#Verifies if Starfield CA is trusted
    if (((get-childitem -path cert:\LocalMachine\AuthRoot | Select-String "Starfield").count -ne 1) -or
    (get-childitem -path cert:\LocalMachine\Root | Select-String "Starfield").count -ne 1) {
    Write-Output "`nRequired 'Starfield Services Root Certificate Authority' missing in certificate store, please obtain it from a working system."
    Auto-CA-update-check 
    $null = Stop-Transcript-and-log
    exit 1

}
} elseif ((Get-Process -Name "TaegisSvc.x64").Count -ne 1) {
    Write-Output "`nInstallation validation error: There should be one TaegisSvc.x64 processes running.  Please troubleshoot and repeat installation attempt.  Please open a Taegis XDR chat, ticket, or call Secureworks and provide us the C:\ProgramData\SecureWorks\Taegis_Agent_Install_Log file for analysis."
    $null = Stop-Transcript-and-log
    exit 1

} elseif (((get-childitem -path cert:\LocalMachine\AuthRoot | Select-String "ISRG").count -ne 1) -or
    (get-childitem -path cert:\LocalMachine\Root | Select-String "ISRG").count -ne 1) {
    Write-Output "`nInstallation validation error: Required 'ISRG root X1' missing in certificate store, please obtain it from a working system." 
    Auto-CA-update-check
    $null = Stop-Transcript-and-log
    exit 1
}

else {
    Write-Output "`n==============================`n***Post-install results***`n"
}

#Stores Red Cloak install value as a variable:
$RC = "Dell SecureWorks Red Cloak"
$RCinstalledApp = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -eq $RC }

#Verify if Red Cloak is installed.  If installed, Red Cloak and Ignition will be uninstalled.  If not installed, remaining uninstall code will be skipped:
if ($RCinstalledApp -eq $null) {

Write-Output "PASS: Post-install Taegis agent verification checks successful.  AgentMigrator script completed successfully!"

#Delete msiexec temp install log file:
Remove-Item -Path "C:\ProgramData\SecureWorks\TEMP_Taegis_Agent_Install_Log.txt"

$null = Stop-Transcript-and-log
exit 1

} else {

Write-Output "1) PASS: Post-install Taegis agent verification checks successful.  Proceeding to uninstall Red Cloak:"

#Identified running Red Cloak processes and stops each of them:
    Get-Process |
        Where-Object { $_.Path -like "C:\Program Files (x86)\Dell SecureWorks\*" } |
        Select-Object -Property ProcessName |
        Stop-Process -Force

#Uninstalls Red Cloak and Ignition:
$RC = "Dell SecureWorks Red Cloak"
$Ignition = "Dell SecureWorks Ignition"
$RC_ID_num = Get-WmiObject -Class Win32_Product | Where-Object Name -eq "$RC" | Select -ExpandProperty IdentifyingNumber
$RC_Ignition = Get-WmiObject -Class Win32_Product | Where-Object Name -eq "$Ignition" | Select -ExpandProperty IdentifyingNumber

#Executes uninstall from CMD and produces uninstall log file to review if errors occur:
cmd.exe /c msiexec /x$RC_ID_num /quiet /l*vx C:\ProgramData\SecureWorks\RC-uninstall.log
cmd.exe /c msiexec /x$RC_Ignition /quiet /l*vx C:\ProgramData\SecureWorks\RC-Ignition-uninstall.log

$RCinstalledApp = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -eq $RC }
$IgnitioninstalledApp = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -eq $Ignition }

if ($RCinstalledApp -eq $null) {
#Removing Red Cloak uninstaller log file if uninstall successful:
    Remove-Item -Path "C:\ProgramData\SecureWorks\RC-uninstall.log"
}
else {
    Write-Output "ERROR: Red Cloak remains installed, please check C:\ProgramData\SecureWorks\RC-uninstall.log file and contact support."
    $null = Stop-Transcript-and-log
    exit 1

}

if ($IgnitioninstalledApp -eq $null) {
#Removing Red Cloak uninstaller log file if uninstall successful:
    Remove-Item -Path "C:\ProgramData\SecureWorks\RC-Ignition-uninstall.log"
}

else {
    Write-Output "ERROR: Ignition remains installed, please check C:\ProgramData\SecureWorks\RC-Ignition-uninstall.log file and contact support."
    $null = Stop-Transcript-and-log
    exit 1

}
Remove-item 'C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Dell SecureWorks' -Recurse
Write-Output "2) PASS: Red Cloak agent successfully uninstalled, proceeding to registry cleanup steps...`n"

#Clean up remaining registry entries post uninstall:

$Reg_var_1 = "Registry::HKLM\SOFTWARE\RedCloak"
$Reg_var_2 = "Registry::HKLM\SOFTWARE\Dell Secureworks"
$Reg_var_3 = "Registry::HKU\.DEFAULT\Software\Dell Secureworks"
$Reg_var_4 = "Registry::HKU\.DEFAULT\Dell Secureworks"
$Reg_var_5 = "Registry::HKU\S-1-5-18\Software\Dell Secureworks"
$Reg_var_6 = "Registry::HKU\S-1-5-18\Dell Secureworks"
$Reg_var_7 = "Registry::HKCU\SOFTWARE\Dell Secureworks"

$RegistryVariables = @(
    $Reg_var_1,
    $Reg_var_2,
    $Reg_var_3,
    $Reg_var_4,
    $Reg_var_5,
    $Reg_var_6,
    $Reg_var_7
)

# Loop through each registry variable for removal
foreach ($RegistryVariable in $RegistryVariables) {
    if (Test-Path $RegistryVariable) {
        Write-Output "Registry entry exists: $RegistryVariable, and has been deleted."
        Remove-Item -Path $RegistryVariable -Recurse -Force
    }
}

#Validating if MS Defender is running and if so, remove Red Cloak agent exclusions for it:
$service = Get-Service -Name WinDefend

if ($service.Status -eq 'Running') {
$exclusionPaths = (Get-MpPreference).ExclusionPath

foreach ($path in $exclusionPaths) {
    if ($path -like '*\Dell SecureWorks\*') {
        Write-Output "`nMS Defender exclusions for Red Cloak $path will now be removed." 
        Remove-MpPreference -ExclusionPath $path
    }
}
}
Write-Output "`n3) PASS: All Red cloak registry entries removed."
Write-Output "4) PASS: AgentMigrator script completed successfully!"
}

#Delete msiexec temp install log file:
Remove-Item -Path "C:\ProgramData\SecureWorks\TEMP_Taegis_Agent_Install_Log.txt"

$null = Stop-Transcript-and-log