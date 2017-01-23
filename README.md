# PowerShell ToolBox
A collection of tools and functions to assist in everyday network administration.

Required Software:
PowerShell v2 or higher

AND
Remote Server Administration Tools on Win 10 https://www.microsoft.com/en-us/download/details.aspx?id=45520

OR
 Remote Server Administration Tools on Win 7 http://www.microsoft.com/download/en/details.aspx?id=7887
	
Tips:
- For best results this script should be run with elevated priveleges
- DNS duplicate record finding tool requires final confirmation until I can work out the PowerShell string comparison logic.
	- BE SURE to review the results as false positives may occur i.e. 192.168.0.182 will trigger false positive for 192.168.0.18 as well.


## Change Log
#### 1/23/2017 Rolling
- Uniformed location to the user's Documents folder for all CSV reports generated from the reports menu.
- Added Folder/File existence test to the reports menu.
- Added Copy, delete and rename features to the MISC. menu.
- Added a resync time command to the MISC. menu. (May be moved later)
- Added a Yes/No module to prompt simple confirmations in various features.
- Fixed DNS audit to no longer prompt for false duplicate DNS entires.

#### 1/11/2017 Current
- The toolbox is provided with a script and a module format.
- Menu selection names have been changed to a more Windows friendly theme.
- Domain Controller will be dynamically selected based on your domain's Primary DC.
- Domain is now dynamically selected via PS engine function.
- A warning will be displayed if the Satellites (Specific targets) array is empty.
- New Menu choice "Misc." has been added for odd jobs such as copy files/folders/etc. as well as deletion. More to come!
- Output will now display the DNS name as well as the IP address of each machine that is touched per job.
- Users can now exlcude specific names from profile removal jobs to avoid losing any profile data.
- Admin profiles with .domain (Administrator.domain) will now be exculded as well as the local Admin (Administrator) account.
- User accounts with a .domain (User.domain) will be excluded from profile removal jobs.
- Profile folder objects are now properly renamed with a new method to avoid triggering the .net character limit.

#### 10/11/2016
- Profile cleaner is now more reliable by utilizing the win32_profile class to remove profiles via SID.
- Residual profile folders are cleaned up with a second sweep after profiles are removed via SID.
- Profile entries are removed from the regisrty as well.
- There are protected profiles in an array in the top of the script. Please use this to avoid incorrect profile removal.

#### 9/26/2016
- Fixed typo that caused host selection to work improperly when selecting servers.

#### 9/16/2016
- Added support for Active Directory based host lookup.
- Added blacklisting by IP support.
- Lowered strict mode to version 2 for compatiblity with Windows 7.
- Roaming profile cleaner is still being refined to ensure issues with the character limit do not break folder deletion.

#### 9/14/2016
- Created new repository.
- Added support for IP ranges to be used in target selection.
- Program un-installer has been disabled due to Win32_product class issues.
