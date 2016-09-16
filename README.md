# KTFCU-PS-SUITE
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
#### 9/16/2016
- Added support for Active Directory based host lookup.
- Added blacklisting by IP support.
- Lowered strict mode to version 2 for compatiblity with Windows 7.
- Roaming profile cleaner is still being refined to ensure issues with the character limit do not break folder deletion.

#### 9/14/2016
- Created new repository.
- Added support for IP ranges to be used in target selection.
- Program un-installer has been disabled due to Win32_product class issues.
