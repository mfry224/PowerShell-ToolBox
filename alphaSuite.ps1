<#
	PowerShell Suite alpha
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
	- For best results this script should be run with elevated priveleges
	- DNS duplicate record finding tool requires final confirmation until I can work out the PowerShell string comparison logic.
		- BE SURE to review the results as false positives may occur i.e. 192.168.0.182 will trigger false positive for 192.168.0.18 as well.

	TODO:
	- Alot :P
#>
$host.UI.RawUI.WindowTitle = "PS-Suite Alpha | Loading...";

<# These are required for DNS Record maintenance only but why not enter them anyway :/ #>
$KTFCU_dcname = "";
$KTFCU_domainLocal = "";

<# These profiles need to be protected from deletion #>
$protAccts = @("administrator","NETWORK SERVICE","LOCAL SERVICE","SYSTEM","$domainName","$finalUser");

<# List all IPs here that you want to be left out of this tool #>
$KTFCU_blackList = @("","","");

<# You may add a custom array of IPs within this array #>
$KTFCU_locationA = @(
	"","",""
);

function KTFCU_fnc_privCheck ()
{
	$userObject = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());
	<# User is using the session as administrator #>
	if ($userObject.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
		if (!$host.UI.RawUI.WindowTitle.StartsWith("Administrator: ")) {
			$host.UI.RawUI.WindowTitle = "Administrator: " + $host.UI.RawUI.WindowTitle;
		};
		write-host "PS-Suite: PowerShell is currently running as Administrator!`n";
		write-host "";

		write-host "PS-Suite: Checking remote management settings. Please wait...`n";
		Enable-PSRemoting -force
		Set-StrictMode -Version 2
		write-host "";

		sleep 3;

		return "true"
	};
	<# User is not using the session as administrator #>
	if (($userObject.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) -ne "Administrator") {
		write-host "PS-Suite: PowerShell is not running as Administrator!`n";
		write-host "PS-Suite: Functionality will be limited!`n";
		write-host "";

		write-host "PS-Suite: Checking remote management settings. Please wait...`n";
		Enable-PSRemoting -force
		Set-StrictMode -Version 2

		sleep 3;

		return "false"
	};
};

function KTFCU_fnc_setPath ()
{
	$newPath = $null
	if ([IntPtr]::size * 8 -eq 64) {
		$host.UI.RawUI.WindowTitle = "PS-Suite Alpha | Windows PowerShell (x64)";
		$newPath = "${env:programfiles(x86)}\Utilities";
	} else {
		$host.UI.RawUI.WindowTitle = "PS-Suite Alpha | Windows PowerShell (x86)";
		$newPath = "${env:programfiles}\Utilities";
	};
	if ((Test-Path $newPath) -and !($env:path -match $newPath.Replace("\","\\")) ) {
		$env:path = "$utilities;${env:path}";
	};
};

function KTFCU_fnc_ipRange
{
	write-host "For a range of targets use the format xxx.xxx.xxx.xxx-xxx`n";
    $ipPrompt = read-host "Enter the range of IPs to use";

    $octSplit = $ipPrompt.Split(".");
    $ipSplit = $ipPrompt.Split("-");
    $finalOct = $octSplit[3].Split("-");

    $ipNet = $octSplit[0]+"."+$octSplit[1]+"."+$octSplit[2];

    $ipRange = $finalOct[0]..$ipSplit[1] | % {"$ipNet.$_"};

    return $ipRange
};

function KTFCU_fnc_adComputers
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
	if ($type -eq 'locA') {
		return $KTFCU_locationA
	};
};

function KTFCU_fnc_hostFind ()
{
	&KTFCU_fnc_header;

	$isAlive = @();
	$testHosts = @();
	$targetHost = "";

	$msgPrompt = "`n";
	$locPrompt = "Please select the target(s) to include";

	$locOption = new-object collections.objectmodel.collection[management.automation.host.choicedescription];

	$locOption.add((new-object management.automation.host.choicedescription -argumentlist "&Alpha Site"));
	$locOption.add((new-object management.automation.host.choicedescription -argumentlist "&Workstations"));
	$locOption.add((new-object management.automation.host.choicedescription -argumentlist "&Servers"));
	$locOption.add((new-object management.automation.host.choicedescription -argumentlist "&Range of IPs"));
	$locOption.add((new-object management.automation.host.choicedescription -argumentlist "Single &IP"));

	$ktfcu_locSelect = $host.ui.promptforchoice($locPrompt, $msgPrompt, $locOption, 4);
	write-host "`n";

	switch ($ktfcu_locSelect) {
		0 {$testHosts = &KTFCU_fnc_adComputers -type 'locA'};
		1 {$testHosts = &KTFCU_fnc_adComputers -type 'pcs'};
		2 {$testHosts = &KTFCU_fnc_adComputers -type 'servers'};
		3 {$testHosts = &KTFCU_fnc_ipRange;};
		4 {
			$targetHost = read-host -prompt "Please enter the IP address of the host machine";
			$testHosts = [string]$targetHost;
		};
	};

	write-host "Attempting to contact the selected machines. Please wait...`n"

	forEach ($i in $testHosts)
	{
		if (!($KTFCU_blackList -contains $i)) {
			$checkState = test-connection $i -count 2 -quiet;
			if ($checkState) {
				$isAlive = [array]$isAlive += $i;
				write-host "Host $i is Online!" -foreground "Green";
			} else {
				write-host "Host $i is Unreachable!" -foreground "Red";
			};
		} else {
			write-host "Host $i is blacklisted!" -foreground "Yellow";
		};
	};
	write-host "`n";
	return $isAlive
};

function KTFCU_fnc_header
{
	clear;
	write-host "";
	write-host "PS-Suite: Welcome to PS-Suite Alpha!";
	write-host "PS-Suite: PS-Suite is currently in an alpha state.";
	write-host "PS-Suite: Please report any issues on the git page.";
	write-host "PS-Suite: For real time updates please subscribe!";
	write-host "PS-Suite: https://github.com/mfry224/";
	write-host "";
	write-host "Disclaimer: This software is in an Alpha state and may cause harm to your systems and/or network if not used properly!`n            Always be mindful of what you are doing and look twice...smash your keyboard once ;)" -foreground "Yellow";
	write-host "`n";
};
function KTFCU_fnc_menuMain
{
	&KTFCU_fnc_setPath;
	&KTFCU_fnc_header;

	write-host "  --  Main Menu  -- `n";

	switch (KTFCU_fnc_prompt -menuOpts @("Software Management","Admin Toolbox"))
	{
		0 {&KTFCU_fnc_softMenu;};
		1 {&KTFCU_fnc_toolsMain;};
		2 {
			write-host "";
			write-host "Thank you for using the PS-Suite for Windows Powershell!`n";
			sleep -s 3;
		};
	};
};
function KTFCU_fnc_softMenu ()
{
	<# User input from software manager menu will be used here #>
	switch (KTFCU_fnc_progMenu) {
		<# User chose to install software #>
		0
		{
			switch (KTFCU_fnc_appMenu)
			{
				<# Add your software here if you want to deploy it to a large number of clients or even a single target for testing #>
				'1'
				{
					forEach ($i in KTFCU_fnc_hostFind) {
						write-host "Adobe Reader 11.0.10 will now be installed on $i!";
						&Start-Process "\\server\path\to \software\program.exe" "/quiet /norestart /otherOptions";
					};
				};
			};
		};
		<# User chose to remove software #>
		1
		{
			<# DO NOT USE THIS as win32_product is known to cause unintended behaviors #>
			<# Prompt user to type name of software. Functions more like a search rather than specific name lookup #>
			<# $ktfcu_appPrompt = read-host "Please enter the name of the software you want to remove";
			forEach ($i in KTFCU_fnc_hostFind)
			{
				$ktfcu_isAlive = test-connection $i -count 2 -quiet;
				if ($ktfcu_isAlive) {

					$ktfcu_appFound = gwmi win32_product -computer $i -filter "Name LIKE '%$ktfcu_appPrompt%'";
					if ($ktfcu_appFound) {

						$ktfcu_appID = $ktfcu_appFound.IdentifyingNumber;
						$ktfcu_appName = $ktfcu_appFound.Name;
						$ktfcu_appVersion = $ktfcu_appFound.Version;

						$classKey="IdentifyingNumber=`"$ktfcu_appID`",Name=`"$ktfcu_appName`",version=`"$ktfcu_appVersion`"";

						write-host "$ktfcu_appName has been found on $i!" -foreground "Green";
						write-host "`n";
						write-host "Application Name: $ktfcu_appName" -foreground "Green";
						write-host "Application Version: $ktfcu_appVersion" -foreground "Green";
						write-host "Application ID: $ktfcu_appID" -foreground "Green";
						write-host "`n";

						([wmi]"\\$i\root\cimv2:Win32_Product.$classKey").uninstall();
					} else {
						write-host "Warning: Application was not found on $i!" -foreground "Yellow";
						write-host "`n";
					}
				} else {
					write-host "Error: Host $i is Unreachable!" -foreground "Red";
					write-host "`n";
					write-host "`n";
				}
			} #>
		}
		<# User chose to view installed programs #>
		2
		{
			$array = @();
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
					$obj | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $computername;
					$obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $($thisSubKey.GetValue("DisplayName"));
					$obj | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value $($thisSubKey.GetValue("DisplayVersion"));
					$obj | Add-Member -MemberType NoteProperty -Name "InstallLocation" -Value $($thisSubKey.GetValue("InstallLocation"));
					$obj | Add-Member -MemberType NoteProperty -Name "Publisher" -Value $($thisSubKey.GetValue("Publisher"));

					$array += $obj;
				};
				$array | Where-Object { $_.DisplayName } | select ComputerName, DisplayName, DisplayVersion, Publisher | ft -auto
			};
		};
	};
};
function KTFCU_fnc_prompt {
	param (
		[Parameter(Mandatory=$true)][array]$menuOpts
    );

	$msgMsg = "";
	$msgTitle = "";

	$userMenu = new-object collections.objectmodel.collection[management.automation.host.choicedescription];

	<# Create a dynamically sized option selection for selected menu #>
	forEach ($i in $menuOpts) {
		$userMenu.add((new-object management.automation.host.choicedescription -argumentlist "`&$i"));
	};

	<# Quit is always an option regardless of menu #>
	$userMenu.add((new-object management.automation.host.choicedescription -argumentlist "`&Quit"));

	$userPrompt = $host.ui.promptforchoice($msgMsg,$msgTitle,$userMenu,($menuOpts).count);

	return $userPrompt
}
function KTFCU_fnc_progMenu ()
{
	$host.UI.RawUI.WindowTitle = "PS-Suite Alpha | Software Management Menu | Windows PowerShell (x64)";
	&KTFCU_fnc_header;

	write-host "  --  Software Management Menu  -- `n";
	KTFCU_fnc_prompt -menuOpts @("Install","Uninstall","View Installed");
}
function KTFCU_fnc_appMenu
{
	$host.UI.RawUI.WindowTitle = "PS-Suite Alpha | Software Installation Menu | Windows PowerShell (x64)";
	&KTFCU_fnc_header;

	write-host "Note: This menu will be more dynamic in future updates and currently must be configured for specific packages!`n" -foreground "Yellow";

	write-host "  --  Software Installation Menu  -- `n";

	write-host "Selections:";
	write-host "-[1] Adobe Reader 11.0.10";
	write-host "";
	write-host "-[Q] Main Menu`n";

	$option = read-host "Type your selection and press enter";

	return $option;
}
function KTFCU_fnc_toolsMain
{
	<# Wait for input and execute appropriate menu #>
	switch (KTFCU_fnc_toolsMenu) {
		0 {
			switch (KTFCU_fnc_netshMenu) {
				'1'
				{
					forEach ($i in KTFCU_fnc_hostFind)
					{
						$ktfcu_isAlive = test-connection $i -count 2 -quiet;
						if ($ktfcu_isAlive) {
							&KTFCU_fnc_header;

							write-host "Enabling Teredo settings for host $i`n";
							Invoke-Expression "netsh int teredo set state default";

							write-host "Enabling 6to4 settings for host $i`n";
							Invoke-Expression "netsh int 6to4 set state default";

							write-host "Enabling ISATAP settings for host $i`n";
							Invoke-Expression "netsh int isatap set state default";

						}
					}
				}
				'2'
				{
					forEach ($i in KTFCU_fnc_hostFind)
					{
						$ktfcu_isAlive = test-connection $i -count 2 -quiet;
						if ($ktfcu_isAlive) {
							&KTFCU_fnc_header;

							write-host "Disabling Teredo settings for host $i`n";
							Invoke-Expression "netsh int teredo set state disabled";

							write-host "Disabling 6to4 settings for host $i`n";
							Invoke-Expression "netsh int 6to4 set state disabled";

							write-host "Disabling ISATAP settings for host $i`n";
							Invoke-Expression "netsh int isatap set state disabled";
						}
					}
				}
			}
			read-host "Press any key to return to the main menu";
		}
		1 {
			switch (ktfcu_fnc_dnsMenu) {
				'1'
				{
					forEach ($i in KTFCU_fnc_hostFind)
					{
						$ktfcu_isAlive = test-connection $i -count 2 -quiet;
						if ($ktfcu_isAlive) {
							&KTFCU_fnc_header;
							write-host "Now registering DNS for host $i`n"
							Invoke-Expression "ipconfig /registerdns"
						}
					}
				}
				'2'
				{
					forEach ($i in KTFCU_fnc_hostFind)
					{
						$ktfcu_isAlive = test-connection $i -count 2 -quiet;
						if ($ktfcu_isAlive) {
							&KTFCU_fnc_header;
							write-host "Now flushing DNS for host $i`n"
							Invoke-Expression "ipconfig /flushdns"
						}
					}
				}
				'3'
				{
					&KTFCU_fnc_header;

					write-host "PS-Suite: Please wait while your DNS records are being parsed.`n";
					forEach ($i in KTFCU_fnc_hostFind)
					{
						write-host "PS-Suite: Now processing DNS records for IP $i!`n";

						$dnsRecord = Get-DnsServerResourceRecord -ZoneName $KTFCU_domainLocal -ComputerName $KTFCU_dcname -RRType "A" | select HostName,@{Name='RecordData';Expression={$_.RecordData.IPv4Address.ToString()}} | Where {$_.RecordData -match $i};
						<# $dnsHost = Get-DnsServerResourceRecord -ZoneName $KTFCU_domainLocal -ComputerName $KTFCU_dcname -RRType "A" | select HostName,@{Name='RecordData';Expression={$_.RecordData.IPv4Address.ToString()}} | Where {$_.RecordData -match $i}; #>

						if (($dnsRecord.RecordData).count -gt 1 -and ($dnsRecord.HostName -ne "@") -and ($dnsRecord.HostName -eq "TAG")) {
							forEach ($i in $dnsRecord.HostName)
							{
								write-host "PS-Suite: Duplicate DNS A records found for host $i!" -foreground 'Yellow';
								write-host "PS-Suite: DNS entries for host(s)"$dnsRecord.HostName"will now be removed!";
								write-host "PS-Suite: New dynamic DNS entries will be created automatically unless you only use static DNS entries.`n";

								write-host "PS-Suite: Now removing DNS record for host $i!" -foreground 'Yellow';

								Remove-DnsServerResourceRecord -ZoneName $KTFCU_domainLocal -ComputerName $KTFCU_dcname -RRType "A" -Name $i;

								Invoke-Expression "ipconfig /flushdns";
								Invoke-Expression "ipconfig /registerdns";
								Write-Host "`n";
							};
						} ElseIf (($dnsRecord.RecordData).count -lt 2) {
							write-host "PS-Suite: There are no duplicate DNS A records detected on $KTFCU_dcname@$KTFCU_domainLocal for $i`n" -foreground "Green";
						};
					};
				};
			};
			read-host "Press any key to return to the main menu";
		};
		2 {
			switch (ktfcu_fnc_gpoMenu) {
				'1'
				{
					forEach ($i in KTFCU_fnc_hostFind)
					{
						$ktfcu_isAlive = test-connection $i -count 2 -quiet
						if ($ktfcu_isAlive) {
							&KTFCU_fnc_header;
							write-host "Updating Group Policy for host $i`n"
							Invoke-Expression "gpupdate /force"
						}
					}
				}
				'2'
				{
					forEach ($i in KTFCU_fnc_hostFind)
					{
						$ktfcu_isAlive = test-connection $i -count 2 -quiet
						if ($ktfcu_isAlive) {
							&KTFCU_fnc_header;
							write-host "Updating Group Policy for host $i`n"
							Invoke-Expression "gpupdate /boot"
						}
					}
				}
				'3'
				{
					forEach ($i in KTFCU_fnc_hostFind)
					{
						$ktfcu_isAlive = test-connection $i -count 2 -quiet
						if ($ktfcu_isAlive) {
							&KTFCU_fnc_header;
							write-host "Updating Group Policy for host $i`n"
							Invoke-Expression "gpupdate /force /boot"
						}
					}
				}
			}
		}
		3 {
			&ktfcu_fnc_remreg_menu
			write-host "`n"

			$input_remreg = read-host "Please select an option"
			write-host "`n"

			switch ($input_remreg) {
				'1'
				{
					forEach ($i in KTFCU_fnc_hostFind)
					{
						$ktfcu_isAlive = test-connection $i -count 2 -quiet
						if ($ktfcu_isAlive) {
							&KTFCU_fnc_header;
							write-host "Enabling remote registry service for host $i`n"
							(Get-WmiObject -computer $i Win32_Service -Filter "Name='RemoteRegistry'").InvokeMethod("StartService",$null)
						}
					}
				}
				'2'
				{
					forEach ($i in KTFCU_fnc_hostFind)
					{
						$ktfcu_isAlive = test-connection $i -count 2 -quiet
						if ($ktfcu_isAlive) {
							&KTFCU_fnc_header;
							write-host "Disabling remote registry service for host $i`n"
							(Get-WmiObject -computer $i Win32_Service -Filter "Name='RemoteRegistry'").InvokeMethod("StopService",$null)
						}
					}
				}
				'3'
				{
					forEach ($i in KTFCU_fnc_hostFind)
					{
						$ktfcu_isAlive = test-connection $i -count 2 -quiet
						if ($ktfcu_isAlive) {
							&KTFCU_fnc_header;
							write-host "Enabling WinRM registry service for host $i`n"
							(Get-WmiObject -computer $i Win32_Service -Filter "Name='WinRM'").InvokeMethod("StartService",$null)
						}
					}
				}
				'4'
				{
					forEach ($i in KTFCU_fnc_hostFind)
					{
						$ktfcu_isAlive = test-connection $i -count 2 -quiet
						if ($ktfcu_isAlive) {
							&KTFCU_fnc_header;
							write-host "Disabling WinRM registry service for host $i`n"
							(Get-WmiObject -computer $i Win32_Service -Filter "Name='WinRM'").InvokeMethod("StopService",$null)
						}
					}
				}
			}
		}
		4 {
			switch (KTFCU_fnc_sysInfo) {
				0 {
					forEach ($i in KTFCU_fnc_hostFind)
					{
						$ktfcu_isAlive = test-connection $i -count 2 -quiet
						if ($ktfcu_isAlive) {
							write-host "Compiling system info for host $i`n"
							$compname = [System.Net.dns]::GetHostbyAddress($i).hostname
							$computer = get-wmiobject Win32_OperatingSystem -ComputerName $compname
							$InstalledDate = $computer.ConvertToDateTime($computer.Installdate)
							$OutputObj  = New-Object -Type PSObject
							$OutputObj | Add-Member -MemberType NoteProperty -Name "Computer Name" -Value $compname
							$OutputObj | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $i
							$OutputObj | Add-Member -MemberType NoteProperty -Name "Installed Date" -Value $InstalledDate.toShortDateString()

							$userName = [Environment]::GetFolderPath("MyDocuments");
							$logPath = ($userName + '\logs');

							if (!(test-path $logPath)) {
								new-item -path $logPath -ItemType directory -force;
							};
							$OutputObj | export-csv -path ($logPath + "systemInfo.csv") -append

							$OutputObj | FL
							write-host "`n"
						}
					}
					Read-Host -Prompt "Press Enter to continue"
				}
				1 {
					write-host "PS-Suite: This tool will remove ALL profiles that are not protected!" -foreground "Red";
					write-host "PS-Suite: Press Ctrl+V repeatadly if you need to cancel this operation!" -foreground "Yellow";
					write-host "`n";
					forEach ($i in KTFCU_fnc_hostFind)
					{
						$strName = Get-WmiObject win32_computersystem -Computer $i | Select -expand username;

						<# Let's check to see if the get object returns a username by counting the string characters to exlcude logged in users from being deleted #>
						if ($strName.length -gt 0) {

							$domainInt = ([Environment]::UserDomainName).length;
							<# The + 1 ensures we cut off the \ after the domain name leaving only the username #>
							$localName = ($strName).Remove(0,(1 + $domainInt));
							$domainName = $localName + '.' + ([Environment]::UserDomainName);

							[string]$curUser = gwmi -ComputerName $i Win32_UserProfile | Select @{Name='localpath';Expression={$_.localpath.ToString()}} | Where {$_.localpath -match $localName}
							#read-host "$curUser"
							$midUser = ($curUser).Remove(0,21);
							#read-host "$midUser"
							[Int]$lengthUser = ($midUser).length;
							#read-host "$lengthUser"
							$finalUser = ($midUser).Remove(($lengthUser - 1),1);
							#read-host "$finalUser"

							$name = Get-Random -minimum 1 -maximum 9999;
							$folders = Get-ChildItem -Path "\\$i\C$\Users\" -Exclude admin*,public*,default*,'All Users',$finalUser;

							write-host "PS-Suite: Logged on user detected!`n";
							write-host "PS-Suite: $finalUser has been excluded from folder deletion for host $i`n";

							$Profiles = Get-WmiObject -Class Win32_UserProfile -Computer $i -ea 0;

							<# Clean out all users accounts by SID #>
							foreach ($profile in $profiles) {
								$objSID = New-Object System.Security.Principal.SecurityIdentifier($profile.sid);
								$objuser = $objsid.Translate([System.Security.Principal.NTAccount]);
								$profilename = $objuser.value.split("\")[1];
								if ($protAccts -contains $profilename) {
									Write-Host "$profilename is protected!`n" -foreground "Yellow";
								} else {
									$profile.delete();
									Write-Host "$profilename deleted successfully on $i`n";
								};
							};

							<# If the folder path\length is too long let's rename it to then be deleted without error while excluding loggred in user #>
							foreach ($folder in $folders){

								$subFolders = Get-ChildItem -Path $folder"\*" -Exclude $folder;
								foreach ($subFolder in $subFolders){
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
								Remove-Item -Force -Verbose -Recurse -Path $folder;
								write-host "`n";
							};
						} else {

							<# The username string was less than 0 or null meaning there is no logged in user so let's delete all profiles that should not be there #>
							$name = Get-Random -minimum 1 -maximum 9999;
							$folders = Get-ChildItem -Path "\\$i\C$\Users\" -Exclude admin*,public*,default*,'All Users';

							write-host "PS-Suite: No logged on users detected!`n";
							
							$Profiles = Get-WmiObject -Class Win32_UserProfile -Computer $i -ea 0;

							<# Clean out all users accounts by SID #>
							foreach ($profile in $profiles) {
								$objSID = New-Object System.Security.Principal.SecurityIdentifier($profile.sid);
								$objuser = $objsid.Translate([System.Security.Principal.NTAccount]);
								$profilename = $objuser.value.split("\")[1];
								if ($protAccts -contains $profilename) {
									Write-Host "$profilename is protected!`n" -foreground "Yellow";
								} else {
									$profile.delete();
									Write-Host "$profilename deleted successfully on $i`n";
								};
							};
							
							<# We will clean out the user folders that have no corresponding profile SID #>
							foreach ($folder in $folders){

								$subFolders = Get-ChildItem -Path $folder"\*" -Exclude $folder;
								foreach ($subFolder in $subFolders){
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
								Remove-Item -Force -Verbose -Recurse -Path $folder;
								write-host "`n";
							};
						};
						write-host "`n";
						read-host "PS-Suite: user folder deletion is complete. Please press any key to return to the main menu";
					};
				}
				2 {
					$filePrompt = read-host "Enter all filenames seperated by commas";
                    $pathPrompt = read-host "Enter all paths seperated by commas";

					forEach ($i in KTFCU_fnc_hostFind)
					{
						function KTFCU_fnc_fileManagement {
							param (
								[Parameter(Mandatory=$true)][array]$fileOpts,
                                [Parameter(Mandatory=$true)][array]$pathOpts
							);

                            $userFiles = @();
                            $findPaths = @();

						    $fileParts = $filePrompt.Split(",");
                            $pathParts = $pathPrompt.Split(",");

						    for ($x = 0; $x -lt $fileParts.Count; $x++){
							    $userFiles = $userFiles += $fileParts[$x];
						    };
                            for ($x = 0; $x -lt $pathParts.Count; $x++){
							    $findPaths = $findPaths += "\\$i\C$\"+$pathParts[$x];
						    };

							$delArrays = @();

                            if (($findPaths).count -lt 2) {
								forEach ($userFile in $userFiles) {
									$findFiles = Get-ChildItem -Path $findPaths -verbose | Where {$_.Name -match $userFiles};
									remove-item -whatif -path $findPaths"\"$userFiles -verbose;
								};
                            } else {
							    forEach ($findPath in $findPaths) {
								    forEach ($userFile in $userFiles) {
									    $findFiles = Get-ChildItem -Path $findPath -verbose | Where {$_.Name -match $userFile}
									    write-host "`n";
									    $delArrays = $delArrays += $findFiles;
                                        write-host "`n";
								    };
								    forEach ($delArray in $delArrays) {
									    remove-item -whatif -path $findPath"\"$delArray -verbose <# -ErrorAction SilentlyContinue #>;
								    };
							    };
                            };
						};
						&KTFCU_fnc_fileManagement -pathOpts $pathPrompt -fileOpts $filePrompt;
					};
					read-host "Pausing";
				};
			};
		};
	};
};
function KTFCU_fnc_toolsMenu
{
	$host.UI.RawUI.WindowTitle = "PS-Suite Alpha | Toolbox Menu | Windows PowerShell (x64)"
	&KTFCU_fnc_header;

	write-host "  --  Toolbox Menu  -- `n"
	KTFCU_fnc_prompt -menuOpts @("Network","DNS","Group Policies","Registry","Systems")
}
function KTFCU_fnc_netshMenu
{
	&KTFCU_fnc_header

	write-host "  --  NETSH Tools Menu  -- `n"

	write-host "Selections:";
	write-host "-[1] Enable IPv6"
	write-host "-[2] Disable IPv6"
	write-host ""
	write-host "-[Q] Main Menu`n"

	$option = read-host "Type your selection and press enter"

	return $option
}
function KTFCU_fnc_dnsMenu
{
	&KTFCU_fnc_header

	write-host "  --  DNS Tools Menu  -- `n"

	write-host "Selections:";
	write-host "-[1] Register DNS"
	write-host "-[2] Flush DNS"
	write-host "-[3] DNS Zone Lookup"
	write-host ""
	write-host "-[Q] Main Menu`n"

	$option = read-host "Type your selection and press enter"

	return $option
}
function KTFCU_fnc_gpoMenu
{
	&KTFCU_fnc_header

	write-host "  --  Group Policy Tools Menu  -- `n"

	write-host "Selections:";
	write-host "-[1] Update Group Policy with /force param"
	write-host "-[2] Update Group Policy with /boot param"
	write-host "-[3] Update Group Policy with /force /boot param"
	write-host ""
	write-host "-[Q] Main Menu`n"

	$option = read-host "Type your selection and press enter"

	return $option
}
function KTFCU_fnc_rmmMenu
{
	&KTFCU_fnc_header

	write-host "  --  Remote Management Tools Menu  -- `n"

	write-host "Selections:";
	write-host "-[1] Enable the remote registry"
	write-host "-[2] Disable the remote registry"
	write-host "-[3] Enable WinRM registry service"
	write-host "-[4] Disable WinRM registry service"
	write-host ""
	write-host "-[Q] Main Menu`n"

	$option = read-host "Type your selection and press enter"

	return $option;
}
function KTFCU_fnc_sysInfo
{
	&KTFCU_fnc_header

	write-host "  --  System Info Tools Menu  -- `n"
	KTFCU_fnc_prompt -menuOpts @("Installation Dates","Clean Roaming Profiles","File Management")
}

<# --------------------------------------------------------------------------------------------------------------- #>
&KTFCU_fnc_header;
&KTFCU_fnc_privCheck;
$userName = [Environment]::GetFolderPath("MyDocuments");
<# This will b needed for the more advanced version when requireing modules. #>
<# $modPath = test-path $userName'\WindowsPowerShell\Modules\menuFunctions' -PathType Any;
& {
	if ($modPath) {
		&import-module active*;
		&import-module menuFunctions;
	};
	if (!$modPath) {
		write-host "PS-Suite: ERROR! - Cannot find Menu Functions! Danger Will Robinson!" -foreground "Red";
		write-host "PS-Suite: Please close this instance and place the menuFunctions.psm1 file in Documents\WindowsPowerShell\Modules folder.`n" -foreground "Yellow";
		write-host "PS-Suite: In a future update PS-Suite will support all native PS module locations.`n" -foreground "Yellow";
	};
}; #>
do {
	KTFCU_fnc_menuMain
}
until (KTFCU_fnc_menuMain -eq 2);
