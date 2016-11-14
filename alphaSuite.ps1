<#
	PowerShell Suite beta
	Suit of tools for administrative network environment usage... or at home ;]
	This script was created with the help of various scripting communities and would not be possible without them

	Required Software:
		PowerShell v2 or higher
	AND
		“Remote Server Administration Tools” on Win 10 https://www.microsoft.com/en-us/download/details.aspx?id=45520
	OR
		“Remote Server Administration Tools” on Win 7 http://www.microsoft.com/download/en/details.aspx?id=7887

	GitHub
	https://github.com/mfry224/

	Tips:
	- For best results this script should be run with elevated privileges
	- DNS duplicate record finding tool requires final confirmation until I can work out the PowerShell string comparison logic.
		- BE SURE to review the results as false positives may occur i.e. 192.168.0.182 will trigger false positive for 192.168.0.18 as well.

	TODO:
	- Alot :P
#>
$host.UI.RawUI.WindowTitle = "KTFCU BetaBox | Initializing...";

<# Array of available domain controllers. Fine to have only one. #>
$KTFCU_myDCs = @("");

<# Domain name i.e. domain.local #>
$KTFCU_domName = "";

<# Array of IPs to be omitted from any operations. #>
$KTFCU_blackList = @();

<# Array of specific IPs to be used in host selection options. You may use this array to target a specific group of IPs.#>
$KTFCU_satellites = @(
	"","",""
);

function KTFCU_fnc_privCheck
{
	clear;
	Write-Host "`n";

	<# Check user's security level and return true/false. #>
	$isElevated = $false;

	$userObject = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());
	<# User is using the session as administrator #>
	if ($userObject.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
		if (!$host.UI.RawUI.WindowTitle.StartsWith("Administrator: ")) {
			$host.UI.RawUI.WindowTitle = "Administrator: " + $host.UI.RawUI.WindowTitle;
		};

		Write-Host "KTFCU BetaBox: Establishing remote management settings. Please wait...`n";
		Enable-PSRemoting -force
		Write-Host "`n";

		$majorVersion = $PSVersionTable.PSVersion.Major;
		Write-Host "KTFCU BetaBox: Establishing strict mode version $majorVersion for shell. Please wait..."
		Set-StrictMode -Version $majorVersion;
		Write-Host "";

		sleep 3;

		$isElevated = $true;
	};
	<# User is not using the session as administrator #>
	if (($userObject.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) -ne "Administrator") {
		Write-Host "KTFCU BetaBox: PowerShell is not running as Administrator!`n" -foreground "Yellow";
		Write-Host "KTFCU BetaBox: Functionality will be limited!`n";
		Write-Host "";

		Write-Host "KTFCU BetaBox: Establishing remote management settings. Please wait...`n";
		Enable-PSRemoting -force
		Write-Host "`n";

		$majorVersion = $PSVersionTable.PSVersion.Major;
		Write-Host "KTFCU BetaBox: Establishing strict mode version $majorVersion for shell. Please wait..."
		Set-StrictMode -Version $majorVersion;
		Write-Host "";

		sleep 3;

		$isElevated = $false;
	};
	return $isElevated
};

function KTFCU_fnc_setPath
{
	$newPath = $null
	if ([IntPtr]::size * 8 -eq 64) {
		$host.UI.RawUI.WindowTitle = "KTFCU BetaBox | Different...On Purpose! (x64)";
		$newPath = "${env:programfiles(x86)}\Utilities";
	} else {
		$host.UI.RawUI.WindowTitle = "KTFCU BetaBox | Different...On Purpose! (x86)";
		$newPath = "${env:programfiles}\Utilities";
	};
	if ((Test-Path $newPath) -and !($env:path -match $newPath.Replace("\","\\")) ) {
		$env:path = "$utilities;${env:path}";
	};
};

function KTFCU_fnc_ipRange
{
	Write-Host "For a range of targets use the format xxx.xxx.xxx.xxx-xxx`n";
    $ipPrompt = read-host "Enter the range of IPs to use";

    $octSplit = $ipPrompt.Split(".");
    $ipSplit = $ipPrompt.Split("-");
    $finalOct = $octSplit[3].Split("-");

    $ipNet = $octSplit[0]+"."+$octSplit[1]+"."+$octSplit[2];

    $ipRange = $finalOct[0]..$ipSplit[1] | % {"$ipNet.$_"};

    return $ipRange
};

function KTFCU_fnc_findTargets
{
	param (
		[Parameter(Mandatory=$true)][array]$type
	);
	$servers = @();
	$pcs = @();
    if ($type -eq 'servers') {
		$srvStrs = Get-ADComputer -Filter {OperatingSystem -Like '*Server*'} -Property ipv4address | Select -expand ipv4address;
		forEach ($srvStr in $srvStrs) {
			if ($srvStr -gt '') {$servers = $servers += $srvStr};
		};
		return $servers
	};
    if ($type -eq 'pcs') {
		$pcsStrs = Get-ADComputer -Filter {OperatingSystem -NotLike '*Server*'} -Property ipv4address | Select -expand ipv4address;
		forEach ($pcsStr in $pcsStrs) {
			if ($pcsStr -gt '') {$pcs = $pcs += $pcsStr};
		};
		return $pcs
	};
	if ($type -eq 'sat') {
		return $KTFCU_satellites
	};
};

function KTFCU_fnc_hostFind
{
	&KTFCU_fnc_header;

	$isAlive = @();
	$testHosts = @();
	$targetHost = "";

	$msgPrompt = "`n";
	$locPrompt = "KTFCU BetaBox: Please select the target(s) to include";

	$locOption = new-object collections.objectmodel.collection[management.automation.host.choicedescription];

	$locOption.add((new-object management.automation.host.choicedescription -argumentlist "S&atellites"));
	$locOption.add((new-object management.automation.host.choicedescription -argumentlist "&Workstations"));
	$locOption.add((new-object management.automation.host.choicedescription -argumentlist "&Servers"));
	$locOption.add((new-object management.automation.host.choicedescription -argumentlist "&Range of IPs"));
	$locOption.add((new-object management.automation.host.choicedescription -argumentlist "Single &IP"));

	$ktfcu_locSelect = $host.ui.promptforchoice($locPrompt, $msgPrompt, $locOption, 4);
	Write-Host "`n";

	switch ($ktfcu_locSelect) {
		0 {$testHosts = &KTFCU_fnc_findTargets -type 'sat'};
		1 {$testHosts = &KTFCU_fnc_findTargets -type 'pcs'};
		2 {$testHosts = &KTFCU_fnc_findTargets -type 'servers'};
		3 {$testHosts = &KTFCU_fnc_ipRange;};
		4 {
			$targetHost = read-host -prompt "Please enter the IP address of the target machine";
			$testHosts = [string]$targetHost;
		};
	};

	Write-Host "Attempting to contact the selected machines. Please wait...`n"

	forEach ($i in $testHosts)
	{
		if (!($KTFCU_blackList -contains $i)) {
			$checkState = test-connection $i -count 2 -quiet;
			if ($checkState) {
				$isAlive = [array]$isAlive += $i;
				Write-Host "Host $i is Online!" -foreground "Green";
			} else {
				Write-Host "Host $i is Unreachable!" -foreground "Red";
			};
		} else {
			Write-Host "Host $i is blacklisted!" -foreground "Yellow";
		};
	};
	Write-Host "`n";
	return $isAlive
};

function KTFCU_fnc_header
{
	clear;
	Write-Host "-----------------------------------------";
	Write-Host "              KTFCU BetaBox              ";
	Write-Host "         Different...On Purpose!         ";
	Write-Host "   Please report issues on the git page  ";
	Write-Host "       https://github.com/mfry224/       ";
	Write-Host "-----------------------------------------";
	Write-Host "`n";
	Write-Host "Don't forget to set your variables in the top of this script!" -foreground "Yellow";
	Write-Host "Be sure to test these tools before using in production!" -foreground "Yellow";
};
<#
function KTFCU_fnc_menuMain
{
	&KTFCU_fnc_setPath;
	&KTFCU_fnc_header;

	Write-Host "`n";
	Write-Host "What would you like to do?";
	Write-Host "`n";

	Write-Host "-[1] Software Management";
	Write-Host "-[2] Administrator Tools";
	Write-Host "`n";

	Write-Host "-[Q] Quit";
	Write-Host "`n";

	$input = read-host "Type your selection and press enter";
	Write-Host "`n";

	switch ($input)
	{
		1
		{
			clear;
			&KTFCU_fnc_softMenuMain;
		};
		2
		{
			clear;
			&KTFCU_fnc_toolsMain;
		};
		'q'
		{
			clear;
			Write-Host "";
			Write-Host "Thank you for using the KTFCU BetaBox for Windows Powershell!`n";
			sleep -s 3;
			clear;
		};
	};
};
 #>
function KTFCU_fnc_menuMain
{
	&KTFCU_fnc_setPath;
	&KTFCU_fnc_header;

	Write-Host "`n";
	Write-Host "What would you like to do?";
	Write-Host "`n";

	Write-Host "-[1] Software Management";
	Write-Host "-[2] IP Management";
	Write-Host "-[3] DNS Management";
	Write-Host "-[4] Services Management";
	Write-Host "-[5] Profile Management";
	Write-Host "`n";

	Write-Host "-[Q] Quit";
	Write-Host "`n";

	$option = read-host "Type your selection and press enter";
	Write-Host "`n";

	switch ($option)
	{
		1 { # Program Tools
			clear;
			&KTFCU_fnc_softMenuMain;
		};
		2 { # IPv6 Tools
			clear;
			&KTFCU_fnc_ipvMenuMain;
		};
		3 { # DNS Tools
			clear;
			&KTFCU_fnc_dnsMenuMain;
		};
		4 { # Services Tools
			clear;
			&KTFCU_fnc_remoteMenuMain;
		};
		5 { # Profile Tools
			clear;
			&KTFCU_fnc_profileMenuMain;
		};
		'q' { # Quit Program
			clear;
			Write-Host "";
			Write-Host "Thank you for using the KTFCU BetaBox for Windows Powershell!`n";
			sleep -s 3;
			clear;
			break;
		};
	};
};

function KTFCU_fnc_softMenuMain
{
	function KTFCU_fnc_softMenu
	{
		&KTFCU_fnc_header;

		Write-Host "  --  Software Management  -- ";
		Write-Host "`n";

		Write-Host "-[1] View Installed Programs";
		Write-Host "-[2] More options coming soon!";
		Write-Host "`n";

		Write-Host "-[Q] Main Menu";
		Write-Host "`n";

		$option = read-host "Type your selection and press enter";

		return $option
	};

	switch (KTFCU_fnc_softMenu) {
		1 {
			<# List all installed software on target(s) #>
			Write-Host "KTFCU BetaBox: Please wait while the list is being populated...";
			Write-Host "`n";

			$KTFCU_regArray = @();
			forEach ($i in KTFCU_fnc_hostFind){

				<# Define the variable to hold the location of Currently Installed Programs #>
				$UninstallKey="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

				<# Create an instance of the Registry Object and open the HKLM base key #>
				$reg=[microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$i);

				<# Drill down into the Uninstall key using the OpenSubKey Method #>
				$regkey=$reg.OpenSubKey($UninstallKey);

				<# Retrieve an array of string that contain all the subkey names #>
				$subkeys=$regkey.GetSubKeyNames();

				<# Open each Subkey and use GetValue Method to return the required values for each #>
				forEach($key in $subkeys) {

					$thisKey=$UninstallKey+"\\"+$key;

					$thisSubKey=$reg.OpenSubKey($thisKey);

					$obj = New-Object PSObject
					$obj | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $i;
					$obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $($thisSubKey.GetValue("DisplayName"));
					$obj | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value $($thisSubKey.GetValue("DisplayVersion"));
					$obj | Add-Member -MemberType NoteProperty -Name "InstallLocation" -Value $($thisSubKey.GetValue("InstallLocation"));
					$obj | Add-Member -MemberType NoteProperty -Name "Publisher" -Value $($thisSubKey.GetValue("Publisher"));

					$KTFCU_regArray += $obj;
				};
			};
			$KTFCU_regArray | Where-Object { $_.DisplayName } | select ComputerName, DisplayName, DisplayVersion, Publisher | ft -auto;
			read-host "KTFCU BetaBox: Press enter to continue";
			&KTFCU_fnc_menuMain;
		};
		'q' { # Main Menu
			&KTFCU_fnc_menuMain;
		};
	};
};

function KTFCU_fnc_ipvMenuMain
{
	function KTFCU_fnc_ipv6Switch
	{
		&KTFCU_fnc_header;

		Write-Host "  --  IPv6 Management  -- ";
		Write-Host "`n";

		Write-Host "-[1] Enable IPv6 for target(s)";
		Write-Host "-[2] Disable IPv6 for target(s)";
		Write-Host "`n";

		Write-Host "-[Q] Main Menu";
		Write-Host "`n";

		$option = read-host "Type your selection and press enter";

		return $option
	};

	switch (KTFCU_fnc_ipv6Switch)
	{
		1 {
			forEach ($i in KTFCU_fnc_hostFind)
			{
				Write-Host "Enabling Teredo settings for host $i`n";
				Invoke-Expression "netsh int teredo set state default";

				Write-Host "Enabling 6to4 settings for host $i`n";
				Invoke-Expression "netsh int 6to4 set state default";

				Write-Host "Enabling ISATAP settings for host $i`n";
				Invoke-Expression "netsh int isatap set state default";
			};
		};
		2 {
			forEach ($i in KTFCU_fnc_hostFind)
			{
				Write-Host "Disabling Teredo settings for host $i`n";
				Invoke-Expression "netsh int teredo set state disabled";

				Write-Host "Disabling 6to4 settings for host $i`n";
				Invoke-Expression "netsh int 6to4 set state disabled";

				Write-Host "Disabling ISATAP settings for host $i`n";
				Invoke-Expression "netsh int isatap set state disabled";
			};
		};
		'q' { # Main Menu
			&KTFCU_fnc_menuMain;
		};
	};
	read-host "KTFCU BetaBox: Press enter to continue";
	&KTFCU_fnc_menuMain;
};

function KTFCU_fnc_dnsMenuMain
{
	function ktfcu_fnc_dnsMenu
	{
		&KTFCU_fnc_header;

		Write-Host "  --  DNS Management  -- ";
		Write-Host "`n";

		Write-Host "-[1] Flush Client DNS Entries";
		Write-Host "-[2] Register Client DNS";
		Write-Host "-[3] DNS Record Maintenance";
		Write-Host "`n";

		Write-Host "-[Q] Main Menu";
		Write-Host "`n";

		$option = read-host "Type your selection and press enter";

		return $option
	};

	switch (ktfcu_fnc_dnsMenu) {
		1 {
			forEach ($i in KTFCU_fnc_hostFind)
			{
				Write-Host "Now flushing DNS for host $i`n";
				Invoke-Expression "ipconfig /flushdns";
			};
		};
		2 {
			forEach ($i in KTFCU_fnc_hostFind)
			{
				Write-Host "Now registering DNS for host $i`n";
				Invoke-Expression "ipconfig /registerdns";
			};
		};
		3 {
			if ($KTFCU_myDCs.count -gt 1) {
				Write-Host "`n";
				Write-Host "KTFCU BetaBox: Support for multiple Domain Controllers is still being developed.";
				Write-Host "KTFCU BetaBox: Please use only one DC for now.";
				Write-Host "`n";
			} else {
				$KTFCU_dcname = $KTFCU_myDCs[0];
			};
			forEach ($i in KTFCU_fnc_hostFind)
			{
				$dnsRecordA = Get-DnsServerResourceRecord -ZoneName $KTFCU_domName -ComputerName $KTFCU_dcname -RRType "A" | select HostName,@{Name='RecordData';Expression={$_.RecordData.IPv4Address.ToString()}} | Where {$_.RecordData -match $i};
				$dnsRecordAAAA = Get-DnsServerResourceRecord -ZoneName $KTFCU_domName -ComputerName $KTFCU_dcname -RRType "AAAA" | select HostName,@{Name='RecordData';Expression={$_.RecordData.IPv6Address.ToString()}} | Where {$_.RecordData -match $i};

				$aRecordIPs = $dnsRecordA.RecordData;
				$aRecordNames = $dnsRecordA.HostName;

				if (($dnsRecordA.RecordData).count -gt 1) {

					forEach ($aRecordIP in $aRecordIPs)
					{
						if ($aRecordIP -eq $i) {
							$aRecordNames = $dnsRecordA.HostName;
							forEach ($aRecordName in $aRecordNames) {
								Write-Host "KTFCU BetaBox: Duplicate DNS A records found for IP $aRecordIP";
								Write-Host "`n";
								Write-Host "KTFCU BetaBox: Host will recreate the A Record entry if not using static records`n";

								Remove-DnsServerResourceRecord -ZoneName $KTFCU_domName -ComputerName $KTFCU_dcname -RRType "A" -Name $aRecordName -confirm:$true -ErrorAction Stop;
							};
							Invoke-Expression "ipconfig /flushdns";
							Invoke-Expression "ipconfig /registerdns";
							Write-Host "`n";
						};
					};
				} ElseIf (($dnsRecordAAAA.RecordData).count -gt 1 -or ($dnsRecordAAAA.HostName).count -gt 1) {

					forEach ($i in $dnsRecordAAAA.RecordData)
					{
						Write-Host "KTFCU BetaBox: Duplicate DNS AAAA records found for"$dnsRecordAAAA.HostName;
						Write-Host "`n";
						Write-Host "KTFCU BetaBox: Host will recreate AAAA Record entry if not using static records`n";

						Remove-DnsServerResourceRecord -ZoneName $KTFCU_domName -ComputerName $KTFCU_dcname -RRType "AAAA" -Name $i -confirm:$true;

						Invoke-Expression "ipconfig /flushdns";
						Invoke-Expression "ipconfig /registerdns";
						Write-Host "`n";
					};
				} else {
					Write-Host "KTFCU BetaBox: There are no duplicate DNS records detected on $KTFCU_dcname@$KTFCU_domName for"$dnsRecordA.HostName;
					Write-Host "`n";
				};
			};
		};
		'q' { # Main Menu
			&KTFCU_fnc_menuMain;
		};
	};
	read-host "Press any key to return to the main menu";
	&KTFCU_fnc_menuMain;
};

function KTFCU_fnc_remoteMenuMain
{
	function KTFCU_fnc_remoteMenu
	{
		&KTFCU_fnc_header;

		Write-Host "  --  Services Management  -- ";
		Write-Host "`n";

		Write-Host "-[1] Enable Remote Registry";
		Write-Host "-[2] Disable Remote Registry";
		Write-Host "-[3] Enable WinRM Service";
		Write-Host "-[4] Disable WinRM Service";
		Write-Host "`n";

		Write-Host "-[Q] Main Menu";
		Write-Host "`n";

		$option = read-host "Type your selection and press enter";

		return $option
	};

	switch (KTFCU_fnc_remoteMenu) {
		1 {
			forEach ($i in KTFCU_fnc_hostFind)
			{
				Write-Host "Enabling remote registry service for target $i`n";
				(Get-WmiObject -computer $i Win32_Service -Filter "Name='RemoteRegistry'").InvokeMethod("StartService",$null);
			};
		};
		2 {
			forEach ($i in KTFCU_fnc_hostFind)
			{
				Write-Host "Disabling remote registry service for target $i`n";
				(Get-WmiObject -computer $i Win32_Service -Filter "Name='RemoteRegistry'").InvokeMethod("StopService",$null);
			};
		};
		3 {
			forEach ($i in KTFCU_fnc_hostFind)
			{
				Write-Host "Enabling WinRM service for target $i`n";
				(Get-WmiObject -computer $i Win32_Service -Filter "Name='WinRM'").InvokeMethod("StartService",$null);
			};
		};
		4 {
			forEach ($i in KTFCU_fnc_hostFind)
			{
				Write-Host "Disabling WinRM service for target $i`n";
				(Get-WmiObject -computer $i Win32_Service -Filter "Name='WinRM'").InvokeMethod("StopService",$null);
			};
		};
		'q' { # Main Menu
			&KTFCU_fnc_menuMain;
		};
	};
	read-host "Press any key to return to the main menu";
	&KTFCU_fnc_menuMain;
};

function KTFCU_fnc_profileMenuMain
{
	function KTFCU_fnc_profileMenu
	{
		&KTFCU_fnc_header;

		Write-Host "  --  Profile Management  -- ";
		Write-Host "`n";

		Write-Host "-[1] Remove Profiles";
		Write-Host "-[2] More features coming soon!";
		Write-Host "`n";

		Write-Host "-[Q] Main Menu";
		Write-Host "`n";

		$option = read-host "Type your selection and press enter";

		return $option
	};

	$dedHosts = @();

	<# These accounts MUST be protected from deletion or risk making system unstable! #>
	<# TODO: Make corresponding var ToUpper for more precise matching. #>
	$KTFCU_sysAccts = @("ADMINISTRATOR","NETWORK SERVICE","LOCAL SERVICE","SYSTEM");

	<# Add any user names you want to be excluded from being removed. #>
	$KTFCU_myAccts = @();

	switch (KTFCU_fnc_profileMenu) {
		1 {
			write-host "`n";
			write-host "KTFCU BetaBox: Please enter any user names, seperated by a comma, to be excluded from profile deletion"
			$KTFCU_addUser = read-host "KTFCU BetaBox: For example suzy,john,matt,ashley";

			$KTFCU_strUsers = $KTFCU_addUser.Split(",");
			forEach ($KTFCU_strUser in $KTFCU_strUsers)
			{
				$cleanUser = $KTFCU_strUser.Trim();
				$KTFCU_myAccts = $KTFCU_myAccts += $cleanUser;
			};

			forEach ($i in KTFCU_fnc_hostFind)
			{
				try {

					Get-WmiObject win32_computersystem -Computer $i -ErrorAction Stop | Out-Null;

					$userName = [Environment]::GetFolderPath("MyDocuments");
					$strName = Get-WmiObject win32_computersystem -Computer $i | Select -expand username;

					<# If username string returns a length of more than 1 a user should be logged in otherwise we will remove all unprotected profiles. #>
					if ($strName.length -gt 1) {

						$localName = $strName.Split("\");
						$userName = $localName[1].Trim();
						$domainName = ([Environment]::UserDomainName);
						$domainName = $userName + "." + $domainName;
						

						Write-Host "`n";
						Write-Host "KTFCU BetaBox: User $userName has been detected on target $i and will not be removed!" -foreground "Yellow";

						$Profiles = Get-WmiObject -Class Win32_UserProfile -Computer $i;
						forEach ($profile in $profiles) {
							
							$objSID = New-Object System.Security.Principal.SecurityIdentifier($profile.sid);
							$objuser = $objsid.Translate([System.Security.Principal.NTAccount]);
							$profilename = $objuser.value.split("\")[1];

							write-host "KTFCU BetaBox: Now processing user $profilename's profile...";
							
							<# Check if profile is in protected array or if profile is current user and skip those. #>
							if (($KTFCU_sysAccts -contains $profilename) -or ($KTFCU_myAccts -contains $profilename) -or ($profilename -match $userName)) {
								Write-Host "KTFCU BetaBox: $profilename is protected and will not be removed!" -foreground "Yellow";
							} else {
								$profile.delete();
								Write-Host "KTFCU BetaBox: $profilename has been removed from target $i";
							};
						};

						<# Rename all residual container objects to reduce path\file name length or risk triggering character limit exception #>
						$name = Get-Random -minimum 1 -maximum 9999;
						$folders = Get-ChildItem -Path "\\$i\C$\Users\" -Exclude Administrator,Administrator.$domainName,$userName,$domainName,Public,Default;

						forEach ($folder in $folders){

							if ($KTFCU_myAccts -notContains $folder) {
								$subFolders = Get-ChildItem -Path $folder"\*" -Exclude $folder;
								forEach ($subFolder in $subFolders){
									Rename-Item -Verbose -Path $subFolder.FullName -NewName "$name";

									if ($subFolder.PSIsContainer){
										$parts = $subFolder.FullName.Split("\")
										$folderPath = $parts[0];
										for ($x = 1; $x -lt $parts.Count - 1; $x++){
											$folderPath = $folderPath + "\" + $parts[$x];
										};
										$folderPath = $folderPath + "\$name";
									};
									$name++;
								};
								Remove-Item -Path $folder -Force -Verbose -Recurse;
								Write-Host "`n";
							} else {
								write-host "KTFCU BetaBox: $folder is protected from deletion!" -foreground "Yellow";
							};
						};
					} else {

						$Profiles = Get-WmiObject -Class Win32_UserProfile -Computer $i;

						<# Filter and remove all profiles that are NOT protected #>
						forEach ($profile in $profiles) {

							$objSID = New-Object System.Security.Principal.SecurityIdentifier($profile.sid);
							$objuser = $objsid.Translate([System.Security.Principal.NTAccount]);
							$profilename = $objuser.value.split("\")[1];

							if (($KTFCU_sysAccts -contains $profilename) -or ($KTFCU_myAccts -contains $profilename)) {
								Write-Host "KTFCU BetaBox: $profilename is protected!" -foreground "Yellow";
							} else {
								$profile.delete();
								Write-Host "KTFCU BetaBox: $profilename deleted successfully from $i";
							};
						};

						<# We will clean out the user folders that have no corresponding profile #>
						$name = Get-Random -minimum 1 -maximum 9999;
						$folders = Get-ChildItem -Path "\\$i\C$\Users\" -Exclude admin*,public*,default*,'All Users';

						forEach ($folder in $folders){
							$subFolders = Get-ChildItem -Path $folder"\*" -Exclude $folder;
							forEach ($subFolder in $subFolders){
								Rename-Item -Verbose -Path $subFolder.FullName -NewName "$name";

								if ($subFolder.PSIsContainer){
									$parts = $subFolder.FullName.Split("\")
									$folderPath = $parts[0];
									for ($x = 1; $x -lt $parts.Count - 1; $x++){
										$folderPath = $folderPath + "\" + $parts[$x];
									}
									$folderPath = $folderPath + "\$name";
								};
								$name++;
							};
							Remove-Item -Path $folder -Force -Verbose -Recurse;
							Write-Host "`n";
						};
					};
				} catch [System.Runtime.InteropServices.COMException] {
				
					Write-Host "`nKTFCU BetaBox: Host at $i is not responding to RPC requests!" -foreground "Red";
					$dedHosts = $dedHosts += $i;
			
				} finally {
					
				};
			};
			write-host "`nHosts that did not respond to RPC requests`n"
			forEach ($dedHost in $dedHosts)
			{
				if ($dedHosts.count -lt 1) {
					write-host "KTFCU BetaBox: There are no targets that did not respond the the RPC requests."
				} else {
					write-host "$dedHost";
				};
				
			};
		};
		2 {
			# Need view profiles here
		};
		'q' { # Main Menu
			&KTFCU_fnc_menuMain;
		};
	};
	read-host "Press any key to return to the main menu";
	&KTFCU_fnc_menuMain;
};

&KTFCU_fnc_privCheck;
&KTFCU_fnc_menuMain;
