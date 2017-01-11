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
function Start-Toolbox
{
	$host.UI.RawUI.WindowTitle = "PS-ToolBox | Initializing...";

	$KTFCU_primaryDC = Get-ADDomainController -Discover -Service "PrimaryDC" | Select-Object -Expand Name;

	$KTFCU_domain = Get-ADDomain | Select-Object -Expand Forest;

	<# Array of IPs to be omitted from any operations. #>
	$KTFCU_blackList = @("132.52.10.10","132.52.10.11","132.52.10.12","132.52.10.112","132.52.10.102");
	$KTFCU_sysAccts = @("NETWORK SERVICE","LOCAL SERVICE","SYSTEM");

	<# Array of specific IPs to be used in host selection options. You may use this array to target a specific group of IPs.#>
	$KTFCU_satellites = @(
		
	);

	if (KTFCU_satellites.Count -eq 0) {
		Write-Host "Warning: The Satellites array is empty. To add a specific set of IPs at the top of the file please close this shell and open the file in your text editor.";
		Read-Host "Press enter to continue";
	};

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

			Write-Host "PS-ToolBox: Establishing remote management settings. Please wait...`n";
			Enable-PSRemoting -force
			Write-Host "`n";

			$majorVersion = $PSVersionTable.PSVersion.Major;
			Write-Host "PS-ToolBox: Establishing strict mode version $majorVersion for shell. Please wait..."
			Set-StrictMode -Version $majorVersion;
			Write-Host "";

			sleep 3;

			$isElevated = $true;
		};
		<# User is not using the session as administrator #>
		if (($userObject.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) -ne "Administrator") {
			Write-Host "PS-ToolBox: PowerShell is not running as Administrator!`n" -foreground "Yellow";
			Write-Host "PS-ToolBox: Functionality will be limited!`n";
			Write-Host "";

			Write-Host "PS-ToolBox: Establishing remote management settings. Please wait...`n";
			Enable-PSRemoting -force
			Write-Host "`n";

			$majorVersion = $PSVersionTable.PSVersion.Major;
			Write-Host "PS-ToolBox: Establishing strict mode version $majorVersion for shell. Please wait..."
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
			$host.UI.RawUI.WindowTitle = "PS-ToolBox | Different...On Purpose! (x64)";
			$newPath = "${env:programfiles(x86)}\Utilities";
		} else {
			$host.UI.RawUI.WindowTitle = "PS-ToolBox | Different...On Purpose! (x86)";
			$newPath = "${env:programfiles}\Utilities";
		};
		if ((Test-Path $newPath) -and !($env:path -match $newPath.Replace("\","\\")) ) {
			$env:path = "$utilities;${env:path}";
		};
	};

	function KTFCU_fnc_ipRange
	{
		Write-Host "PS-ToolBox only supports single subnet IP ranges currently.";
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

	<# TODO: Finish yes/no function to allow for further confirmation from user #>
	function KTCCU_yesNo
	{
		param (
			[Parameter(Mandatory=$true)][string]$question
		);
		
		$promptSpace = "`n";

		$yesNoOption = new-object collections.objectmodel.collection[management.automation.host.choicedescription];

		$yesNoOption.add((new-object management.automation.host.choicedescription -argumentlist "&Yes"));
		$yesNoOption.add((new-object management.automation.host.choicedescription -argumentlist "&No"));
		$yesNoOption.add((new-object management.automation.host.choicedescription -argumentlist "&Quit"));

		$ktfcu_yesNoSelect = $host.ui.promptforchoice($question, $promptSpace, $yesNoOption, 2);
		Write-Host "`n";

		switch ($ktfcu_yesNoSelect) {
			0 {return "Yes";};
			1 {return "No";};
			2 {&KTFCU_fnc_menuMain;};
		};
	}

	function KTFCU_fnc_hostFind
	{
		#&KTFCU_fnc_header;

		$isAlive = @();
		$testHosts = @();
		$targetHost = "";

		$msgPrompt = "`n";
		$locPrompt = "PS-ToolBox: Please select the target(s) to include";

		$locOption = new-object collections.objectmodel.collection[management.automation.host.choicedescription];

		$locOption.add((new-object management.automation.host.choicedescription -argumentlist "S&atellites"));
		$locOption.add((new-object management.automation.host.choicedescription -argumentlist "&Workstations"));
		$locOption.add((new-object management.automation.host.choicedescription -argumentlist "&Servers"));
		$locOption.add((new-object management.automation.host.choicedescription -argumentlist "&Range of IPs"));
		$locOption.add((new-object management.automation.host.choicedescription -argumentlist "Single &IP"));
		$locOption.add((new-object management.automation.host.choicedescription -argumentlist "&Quit"));

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
			5 {&KTFCU_fnc_menuMain;};
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
		Write-Host "              PS-ToolBox              ";
		Write-Host "         Different...On Purpose!         ";
		Write-Host "   Please report issues on the git page  ";
		Write-Host "       https://github.com/mfry224/       ";
		Write-Host "-----------------------------------------";
		Write-Host "`n";
		Write-Host "Be sure to test these tools before using in production!" -foreground "Yellow";
	};

	function KTFCU_fnc_menuMain
	{
		&KTFCU_fnc_setPath;
		&KTFCU_fnc_header;

		Write-Host "`n";
		Write-Host "What would you like to do?";
		Write-Host "`n";

		Write-Host "-[1] Programs and Features";
		Write-Host "-[2] Network Center";
		Write-Host "-[3] DNS Manager";
		Write-Host "-[4] Services";
		Write-Host "-[5] Profile Management";
		Write-Host "-[6] Reports";
		Write-Host "-[7] Misc.";
		Write-Host "`n";

		Write-Host "-[Q] Quit";
		Write-Host "`n";

		$option = read-host "Type your selection and press enter";
		Write-Host "`n";

		switch ($option)
		{
			1 { # Programs and Features
				clear;
				&KTFCU_fnc_softMenuMain;
			};
			2 { # Network Center
				clear;
				&KTFCU_fnc_ipvMenuMain;
			};
			3 { # DNS Manager
				clear;
				&KTFCU_fnc_dnsMenuMain;
			};
			4 { # Services
				clear;
				&KTFCU_fnc_remoteMenuMain;
			};
			5 { # Profile Management
				clear;
				&KTFCU_fnc_profileMenuMain;
			};
			6 { # Reports
				clear;
				&KTFCU_fnc_reportMenuMain;
			};
			6 { # Misc.
				clear;
				&KTFCU_fnc_miscMenuMain;
			};
			'q' { # Quit Program
				clear;
				Write-Host "";
				Write-Host "Thank you for using the PS-ToolBox for Windows Powershell!";
				Write-Host "";
				sleep -s 3;
				clear;
				exit
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
			Write-Host "-[2] Install Program";
			Write-Host "-[2] Uninstall Program";
			Write-Host "`n";

			Write-Host "-[Q] Main Menu";
			Write-Host "`n";

			$option = read-host "Type your selection and press enter";

			return $option
		};

		switch (KTFCU_fnc_softMenu) {
			1 {
				<# List all installed software on target(s) #>
				Write-Host "PS-ToolBox: Please wait while the list is being populated...";
				Write-Host "`n";
				
				forEach ($i in KTFCU_fnc_hostFind){
					$KTFCU_dnsName = [System.Net.dns]::GetHostbyAddress($i).hostname;
					invoke-command -computer $KTFCU_dnsName -scriptblock {
						$KTFCU_regFind = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName
						$KTFCU_regFind | Format-Table -AutoSize;
					};
				};
				
				read-host "PS-ToolBox: Press enter to continue";
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
			1 { # Enabled
				forEach ($i in KTFCU_fnc_hostFind)
				{
					$KTFCU_dnsName = [System.Net.dns]::GetHostbyAddress($i).hostname;
					
					Write-Host "Enabling Teredo settings for host $KTFCU_dnsName [$i]`n";
					#Invoke-Expression "netsh int teredo set state default";
					Invoke-Command -Computer $KTFCU_dnsName -ScriptBlock {
						netsh int teredo set state default
					};

					Write-Host "Enabling 6to4 settings for host $KTFCU_dnsName [$i]`n";
					#Invoke-Expression "netsh int 6to4 set state default";
					Invoke-Command -Computer $KTFCU_dnsName -ScriptBlock {
						netsh int 6to4 set state default
					};
					
					Write-Host "Enabling ISATAP settings for host $KTFCU_dnsName [$i]`n";
					#Invoke-Expression "netsh int isatap set state default";
					Invoke-Command -Computer $KTFCU_dnsName -ScriptBlock {
						netsh int isatap set state default
					};
				};
			};
			2 { # Disabled
				forEach ($i in KTFCU_fnc_hostFind)
				{
					$KTFCU_dnsName = [System.Net.dns]::GetHostbyAddress($i).hostname;
					
					Write-Host "Disabling Teredo settings for host $KTFCU_dnsName [$i]`n";
					#Invoke-Expression "netsh int teredo set state disabled";
					Invoke-Command -Computer $KTFCU_dnsName -ScriptBlock {
						netsh int teredo set state disabled
					};

					Write-Host "Disabling 6to4 settings for host $KTFCU_dnsName [$i]`n";
					#Invoke-Expression "netsh int 6to4 set state disabled";
					Invoke-Command -Computer $KTFCU_dnsName -ScriptBlock {
						netsh int 6to4 set state disabled
					};

					Write-Host "Disabling ISATAP settings for host $KTFCU_dnsName [$i]`n";
					#Invoke-Expression "netsh int isatap set state disabled";
					Invoke-Command -Computer $KTFCU_dnsName -ScriptBlock {
						netsh int isatap set state disabled
					};
				};
			};
			'q' { # Main Menu
				&KTFCU_fnc_menuMain;
			};
		};
		read-host "PS-ToolBox: Press enter to continue";
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
					$KTFCU_dnsName = [System.Net.dns]::GetHostbyAddress($i).hostname;
					Write-Host "Now flushing DNS for host $KTFCU_dnsName [$i]`n";
					Invoke-Expression "ipconfig /flushdns";
				};
			};
			2 {
				forEach ($i in KTFCU_fnc_hostFind)
				{
					$KTFCU_dnsName = [System.Net.dns]::GetHostbyAddress($i).hostname;
					Write-Host "Now registering DNS for host $KTFCU_dnsName [$i]`n";
					Invoke-Expression "ipconfig /registerdns";
				};
			};
			3 {
				forEach ($i in KTFCU_fnc_hostFind)
				{
					$KTFCU_dnsName = [System.Net.dns]::GetHostbyAddress($i).hostname;
					$dnsRecordA = Get-DnsServerResourceRecord -ZoneName $KTFCU_domain -ComputerName $KTFCU_primaryDC -RRType "A" | select HostName,@{Name='RecordData';Expression={$_.RecordData.IPv4Address.ToString()}} | Where {$_.RecordData -eq $i -and $_.HostName -ne "@"};
					$dnsRecordAAAA = Get-DnsServerResourceRecord -ZoneName $KTFCU_domain -ComputerName $KTFCU_primaryDC -RRType "AAAA" | select HostName,@{Name='RecordData';Expression={$_.RecordData.IPv6Address.ToString()}} | Where {$_.RecordData -eq $i -and $_.HostName -ne "@"};

					$aRecordIPs = $dnsRecordA.RecordData;
					$aRecordNames = $dnsRecordA.HostName;

					if (($dnsRecordA.RecordData).count -gt 1) {

						forEach ($aRecordIP in $aRecordIPs)
						{
							if ($aRecordIP -eq $i) {
								$aRecordNames = $dnsRecordA.HostName;
								forEach ($aRecordName in $aRecordNames) {
									Write-Host "PS-ToolBox: Duplicate DNS A records found for IP $aRecordIP";
									Write-Host "`n";
									Write-Host "PS-ToolBox: Host will recreate the A Record entry if not using static records`n";

									Remove-DnsServerResourceRecord -ZoneName $KTFCU_domain -ComputerName $KTFCU_primaryDC -RRType "A" -Name $aRecordName -confirm:$true -ErrorAction Stop;
								};
								Invoke-Expression "ipconfig /flushdns";
								Invoke-Expression "ipconfig /registerdns";
								Write-Host "`n";
							};
						};
					} ElseIf (($dnsRecordAAAA.RecordData).count -gt 1 -or ($dnsRecordAAAA.HostName).count -gt 1) {

						forEach ($i in $dnsRecordAAAA.RecordData)
						{
							Write-Host "PS-ToolBox: Duplicate DNS AAAA records found for"$dnsRecordAAAA.HostName;
							Write-Host "`n";
							Write-Host "PS-ToolBox: Host will recreate AAAA Record entry if not using static records`n";

							Remove-DnsServerResourceRecord -ZoneName $KTFCU_domain -ComputerName $KTFCU_primaryDC -RRType "AAAA" -Name $i -confirm:$true;

							Invoke-Expression "ipconfig /flushdns";
							Invoke-Expression "ipconfig /registerdns";
							Write-Host "`n";
						};
					} else {
						Write-Host "PS-ToolBox: There are no duplicate DNS records detected on $KTFCU_primaryDC@$KTFCU_domain for"$dnsRecordA.HostName;
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

			Write-Host "-[1] Start/Stop Services";
			Write-Host "-[2] Remove Services";
			Write-Host "`n";

			Write-Host "-[Q] Main Menu";
			Write-Host "`n";

			$option = read-host "Type your selection and press enter";

			return $option
		};

		switch (KTFCU_fnc_remoteMenu) {
			1 {
				write-host "`n";
				write-host "PS-ToolBox: Please enter the exact name of the service you wish to manage."
				$userService = read-host "PS-ToolBox: For example, RemoteRegistry or WinRM";
				write-host "`n";
				
				$actionService = read-host "PS-ToolBox: Enter 1 to start service or 2 to stop service";
				write-host "`n";
				
				forEach ($i in KTFCU_fnc_hostFind)
				{
					switch ($actionService) {
						1 {$serviceSwitch = "StartService";};
						2 {$serviceSwitch = "StopService";};
					};
					Write-Host "PS-ToolBox: $userService has been selected for management.Please wait...";
					write-host "`n";
					
					$serviceResult = (Get-WmiObject -computer $i Win32_Service -Filter "Name=""$userService""").InvokeMethod($serviceSwitch,$null);
					
					switch ($serviceResult) {
						0 {
							write-host "PS-ToolBox: Action completed successfully." -foreground "Green";
							write-host "`n";
						};
						10 {
							write-host "PS-ToolBox: Service is already started/stopped!" -foreground "Yellow";
							write-host "`n";
						};
					};
				};
			};
			2 {
				
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
		$KTFCU_sysAccts = @("NETWORK SERVICE","LOCAL SERVICE","SYSTEM");

		<# Add any user names you want to be excluded from being removed. #>
		<# TODO: Make corresponding var ToLower for more precise matching. #>
		$KTFCU_exclude = @("Administrator");

		switch (KTFCU_fnc_profileMenu) {
			1 {
				write-host "`n";
				write-host "PS-ToolBox: Please enter any user names, seperated by a comma, to be excluded from profile deletion"
				$KTFCU_addUser = read-host "PS-ToolBox: For example suzy,john,matt,ashley";

				$KTFCU_strUsers = $KTFCU_addUser.Split(",");
				forEach ($KTFCU_strUser in $KTFCU_strUsers)
				{
					$skipUser = $KTFCU_strUser.Trim();
					$KTFCU_exclude = $KTFCU_exclude += $skipUser;
				};

				forEach ($i in KTFCU_fnc_hostFind)
				{
					<# TODO: Create a progress bar to indicate completion #>
					#Write-Progress -Activity "Removing Profiles..." -Status "Progress:" -PercentComplete $indexCount;

					$isAlive = test-connection $i -count 3 -quiet;

					if ($isAlive) {

						try {

							$targetDNS = [System.Net.dns]::GetHostbyAddress($i).hostname;
							$strName = Get-WmiObject -Class win32_computersystem -Computer $targetDNS -ErrorAction Stop | Select-Object -Expand username;
							$strNameLength = $strName.Length;

							Write-Debug "Username Length`: $strNameLength";

							<# If length of username is 0 there is no current user #>
							if ($strName.Length -gt 0) {

								$domainUser = $strName.Split("\");
								$userName = $domainUser[1].Trim();
								$domainName = $userName + "." + $domain;
								$domainAdmin = "Administrator." + $domain;

								Write-Debug "`n";
								Write-Debug "Domain user`: $domainUser";
								Write-Debug "Username`: $userName";
								Write-Debug "Domain name`: $domainName";
								Write-Debug "`n";

								Write-Host "`n";
								Write-Host "PS-ToolBox: $userName is currently logged on to $targetDNS.";
								Write-Host "`n";

								$profiles = Get-WmiObject -Class Win32_UserProfile -Computer $i -ErrorAction Stop;

								Write-Debug "`n";
								Write-Debug "PS-ToolBox: Profiles detected on $targetDNS`:";
								Write-Debug "$profiles";
								Write-Debug "`n";

								forEach ($profile in $profiles) {

									try {

										$objSID = New-Object System.Security.Principal.SecurityIdentifier($profile.sid);
										$objuser = $objsid.Translate([System.Security.Principal.NTAccount]);
										$profileSplit = $objuser.value.split("\")[1];
										$profileName = $profileSplit.Trim();

										Write-Debug "`n";
										Write-Debug "Profile name`: $profileName";
										Write-Debug "`n";

										<# Skip system and current user profiles #>
										if (($KTFCU_sysAccts -contains $profileName) -or ($KTFCU_exclude -contains $profileName) -or ($profileName -eq $userName) -or ($profileName -eq $domainName) -or ($profileName -eq "Administrator") -or ($profileName -eq $domainAdmin)) {

											Write-Host "PS-ToolBox: The profile for $profileName is protected and will not be altered.";

										} else {

											Write-Host "PS-ToolBox: The profile for $profileName will be removed from $targetDNS." -foreground "Yellow";
											$profile.delete();
										};
									} catch {

									} finally {

									};
								};
								
								$folders = Get-ChildItem -Path "\\$target\C$\Users\" -Exclude Administrator,$domainAdmin,$userName,$profileName,$domainName,Public,Default,"All Users";

								forEach ($folder in $folders){

									<# Rename all folders to avoid triggering container length issue #>
									$alphas = @("a","b","c","d","e","f","g","h","i","j") | Get-Random;
									$numbers = @("0","1","2","3","4","5","6","7","8","9") | Get-Random;

									$name = "$alphas" + "$numbers";

									Write-Debug "`n";
									Write-Debug "Random folder name`: $name";
									Write-Debug "`n";

									<# Remove all profile folders not matching the current user #>
									if ($folder -ne $userName ) {

										$subFolders = Get-ChildItem -Path "$folder\*" -Exclude "$folder";
										forEach ($subFolder in $subFolders){
											Rename-Item -Verbose -Path "$subFolder.FullName" -NewName "$name";

											if ($subFolder.PSIsContainer){
												$parts = $subFolder.FullName.Split("\")
												$folderPath = $parts[0];
												for ($x = 1; $x -lt $parts.Count - 1; $x++){
													$folderPath = $folderPath + "\" + $parts[$x];
												};
												Write-Host "PS-ToolBox: Renaming folder $subFolder to $name" -foreground "Yellow";
												$folderPath = $folderPath + "\$name";
											};
										};
										Remove-Item -Path "$folder" -Force -Verbose -Recurse;
										Write-Host "`n";
									};
								};
							} else {

								Write-Host "`n";
								Write-Host "PS-ToolBox: No user is currently logged on to $targetDNS.`n";

								$Profiles = Get-WmiObject -Class Win32_UserProfile -Computer $i -ErrorAction Stop;

								<# Remove profiles that are not system or admin #>
								forEach ($profile in $profiles) {

									try {

										$objSID = New-Object System.Security.Principal.SecurityIdentifier($profile.sid);
										$objuser = $objsid.Translate([System.Security.Principal.NTAccount]);
										$profileSplit = $objuser.value.split("\")[1];
										$profileName = $profileSplit.Trim();

										if (($KTFCU_sysAccts -contains $profileName) -or ($KTFCU_exclude -contains $profileName) -or ($profileName -eq "Administrator") -or ($profileName -eq $domainAdmin)) {

											Write-Host "PS-ToolBox: The profile for $profileName is protected and will not be altered.";

										} else {

											Write-Host "PS-ToolBox: The profile for $profileName will be removed from $targetDNS." -foreground "Yellow";
											$profile.delete();
										};
									} catch {

									} finally {

									};
								};
								
								$folders = Get-ChildItem -Path "\\$target\C$\Users\" -Exclude Administrator,$domainAdmin,Public,Default,"All Users";

								forEach ($folder in $folders){

									<# Rename all folders to avoid triggering container length issue #>
									$alphas = @("a","b","c","d","e","f","g","h","i","j") | Get-Random;
									$numbers = @("0","1","2","3","4","5","6","7","8","9") | Get-Random;

									$name = $name = "$alphas" + "$numbers";

									Write-Debug "`n";
									Write-Debug "Random folder name`: $name";
									Write-Debug "`n";

									$subFolders = Get-ChildItem -Path "$folder\*" -Exclude "$folder";
									forEach ($subFolder in $subFolders){
										Rename-Item -Verbose -Path "$subFolder.FullName" -NewName "$name";

										if ($subFolder.PSIsContainer){
											$parts = $subFolder.FullName.Split("\")
											$folderPath = $parts[0];
											for ($x = 1; $x -lt $parts.Count - 1; $x++){
												$folderPath = $folderPath + "\" + $parts[$x];
											}
											Write-Host "PS-ToolBox: Renaming folder $subFolder to $name" -foreground "Yellow";
											$folderPath = $folderPath + "\$name";
										};
									};
									Remove-Item -Path "$folder" -Force -Verbose -Recurse;
									Write-Host "`n";
								};
							};
						} catch [System.Runtime.InteropServices.COMException] {

							Write-Host "`n";
							Write-Host "PS-ToolBox: $targetDNS is not responding to RPC requests!" -foreground "Yellow";
							$dedHosts = $dedHosts += $i;

						} finally {

						};
					} else {

						Write-Host "`n"
						write-host "$targetDNS is not responding to ICMP requests!" -foreground "Yellow";
					};
					$indexCount = $indexCount++;
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

	function KTFCU_fnc_reportMenuMain
	{
		function KTFCU_fnc_reportMenu
		{
			&KTFCU_fnc_header;

			Write-Host "  --  Report Management  -- ";
			Write-Host "`n";

			Write-Host "-[1] System Information";
			Write-Host "-[2] More features coming soon!";
			Write-Host "`n";

			Write-Host "-[Q] Main Menu";
			Write-Host "`n";

			$option = read-host "Type your selection and press enter";

			return $option
		};
		
		switch (KTFCU_fnc_reportMenu) {
			1 {
				forEach ($i in KTFCU_fnc_hostFind)
				{			
					$KTFCU_dnsName = [System.Net.dns]::GetHostbyAddress($i).hostname;
					$computer = get-wmiobject Win32_OperatingSystem -ComputerName $KTFCU_dnsName;
					$InstalledDate = $computer.ConvertToDateTime($computer.Installdate);
					
					$Profiles = Get-WmiObject -Class Win32_UserProfile -Computer $i;
					forEach ($profile in $profiles) {

						$objSID = New-Object System.Security.Principal.SecurityIdentifier($profile.sid);
						$objuser = $objsid.Translate([System.Security.Principal.NTAccount]);
						$profilename = $objuser.value.split("\")[1];

						if (($KTFCU_sysAccts -contains $profilename)) {
							Write-Host "PS-ToolBox: Skipping system account profile";
						} else {
							$userProfile = $profilename;
						};
					};
					
					$OutputObj  = New-Object -Type PSObject;
					$OutputObj | Add-Member -MemberType NoteProperty -Name "Computer Name" -Value $KTFCU_dnsName;
					$OutputObj | Add-Member -MemberType NoteProperty -Name "User Name" -Value $userProfile;
					$OutputObj | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $i;
					$OutputObj | Add-Member -MemberType NoteProperty -Name "Installed Date" -Value $InstalledDate.toShortDateString();

					$userName = [Environment]::GetFolderPath("MyDocuments");
					$logPath = "$userName\logs";

					$OutputObj | Format-Table -AutoSize;
					write-host "`n";

					if (!(test-path $logPath)) {
						new-item -path $logPath -ItemType directory -force;
					};
					$OutputObj | export-csv -path $logPath\systemInfo.csv -append;
					
					Clear-Variable $userProfile;
				};
			};
			'q' { # Main Menu
				&KTFCU_fnc_menuMain;
			};
		};
		read-host "Press any key to return to the main menu";
		&KTFCU_fnc_menuMain;
	};

	function KTFCU_fnc_miscMenuMain
	{
		function KTFCU_fnc_miscSwitch
		{
			&KTFCU_fnc_header;

			Write-Host "  --  Miscellaneous Tools  -- ";
			Write-Host "`n";

			Write-Host "-[1] Copy";
			Write-Host "-[2] Delete";
			Write-Host "`n";

			Write-Host "-[Q] Main Menu";
			Write-Host "`n";

			$option = read-host "Type your selection and press enter";

			return $option
		};

		switch (KTFCU_fnc_miscSwitch)
		{
			1 { # Copy
			
				Write-Host "PS-ToolBox: The source path is literal and will be used exactly as typed" -foreground "Yellow";
				$copyFrom = Read-Host "PS-ToolBox: Please enter the full path and name of the source";
				$copyTo = Read-Host "PS-ToolBox: Please enter the full path of the destination";
				
				forEach ($i in KTFCU_fnc_hostFind)
				{
					$KTFCU_dnsName = [System.Net.dns]::GetHostbyAddress($i).hostname;
					Write-Host "Starting copy job for host $KTFCU_dnsName [$i]`n";
					
					if (Test-Path $copyFrom -pathType container) {
						Copy-Item -LiteralPath $copyFrom -Destination $copyTo -Recurse -Verbose;
					} else {
						Copy-Item -LiteralPath $copyFrom -Destination $copyTo -Verbose;
					}
				};
			};
			2 { # Delete
				forEach ($i in KTFCU_fnc_hostFind)
				{
					$KTFCU_dnsName = [System.Net.dns]::GetHostbyAddress($i).hostname;
					
					Write-Host "Starting delete job for host $KTFCU_dnsName [$i]`n";
					Invoke-Command -Computer $KTFCU_dnsName -ScriptBlock {
						
					};
				};
			};
			'q' { # Main Menu
				&KTFCU_fnc_menuMain;
			};
		};
		read-host "PS-ToolBox: Press enter to continue";
		&KTFCU_fnc_menuMain;
	};

	&KTFCU_fnc_privCheck;
	&KTFCU_fnc_menuMain;
};
