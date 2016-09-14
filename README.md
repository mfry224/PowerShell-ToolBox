# KTFCU-PS-SUITE
A collection of tools and functions to assist in everyday network administration.

Required Software:
PowerShell v3 or higher

AND
Remote Server Administration Tools” on Win 10 https://www.microsoft.com/en-us/download/details.aspx?id=45520

OR
 Remote Server Administration Tools” on Win 7 http://www.microsoft.com/download/en/details.aspx?id=7887
	
Tips:
- For best results this script should be run with elevated priveleges
- Add your IPs to the empty arrays before use or use a specific target without any changes to the arrays.
- If you select a program to uninstall it will be removed without final confirmation from user. This will change soon*
- DNS duplicate record finding tool requires final confirmation until I can work out the PowerShell string comparison logic.
- BE SURE to review the results as false positives may occur i.e. 192.168.0.182 will trigger false positive for 192.168.0.18 as well.
