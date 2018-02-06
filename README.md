# OneFS SMB3 Continuous Availability share switcher
This script allows you to easily change an SMB share's continuous availability feature on and off. This script works with OneFS versions 8.0 and above and works both on and off cluster.

## Why is something like this necessary?
OneFS, like Windows Server, can only enable the CA (continuous availability) feature during share creation. Once a share is created it is not possible to alter the CA feature flag without first deleting the share and creating it anew. THe problem with doing this manually is that any slight customizations to the share would have to be re-created on the new share as well and this could be troublesome especially if you have a lot of shares to work through.

## Usage
The script needs to be run at least 2 times to modify the SMB shares. The first time the script is run, it will dump all the existing SMB shares including which Access Zone they belong to into 2 sections. One section for normal SMB shares and a second section for shares that already have the Continuous Availability feature enabled. Each share is written to its own line.

A user should edit the output file and rearrange the shares and put them into the groups that you want the shares to be in as a final result.

*Example output file:*
```
[NORMAL_SHARES]
System,TestShare1,/ifs,
AnotherZoneName,TestShare2,/ifs/data,Optional description of share in AnotherZoneName
    
[CA_SHARES]
System,ifs,/ifs,Isilon OneFS
TestZone,TestShare,/ifs/testzone,This share should be a CA enabled share
```
If you wanted to make __TestShare2__ share a CA share and change the __ifs__ share to a normal share, you would edit the file and it should look like this:
```
[NORMAL_SHARES]
System,TestShare1,/ifs,
System,ifs,/ifs,Isilon OneFS
    
[CA_SHARES]
AnotherZoneName,TestShare2,/ifs/data,Optional description of share in AnotherZoneName
TestZone,TestShare,/ifs/testzone,This share should be a CA enabled share
```
When you run the script again with the __-i__ option and give it the above input, the script will make alter just the __TestShare2__ and __ifs__ shares.


*Example 1 - Run on cluster:*

    python smb_ca_switch.py -o smblist.txt

Edit the smblist.txt file and save as a new file smblist_modified.txt 

    python smb_ca_switch.py -i smblist_modified.txt
    
*Example 2 - Run off cluster:*

    python smb_ca_switch.py -u api_user -p password -s fqdn_or_ip_of_cluster -o smblist.txt

Edit the smblist.txt file and save as a new file smblist_modified.txt


    python smb_ca_switch.py -u api_user -p password -s fqdn_or_ip_of_cluster -o smblist.txt
    
### CLI options
Option|Description
------|-----------
-u, --user|Optional user name to authenticate to the Isilon cluster. Used for off cluster execution. If user is not specified the script will prompt.
-p, --password|Optional password for the user specified above. Used for off cluster execution. If password is not specified the script will prompt.
-s, --server|IP or FQDN of a cluster IP for the script to connect.
-o, --output|When present, the script will output the current SMB share configuration to the file specified here.
-i, --input|When present, the script will perform a share update using the data in the file to alter SMB shares as necessary.
--ignore_mismatch|If the input file does not match the current cluster shares exactly the script normally aborts. When this flag is present the script will continue and do whatever work it can.
--pretend|If present, the script will not alter any SMB shares, but just output what it would do.
-l, --log|Path to a log file.
--console_log|Output log to the console along with a possible file.
-q, --quiet|Minimize screen output.
--debug|Can be specified once or twice. One --debug will turn on INFO level messages while 2 --debug will turn on full debugging.
    
## Limitations and assumptions
* This script only works with OneFS versions 8.0 and above.
* The script currently will only work with a number of shares up to 5000. To go beyond this the code needs to be modified to ask for more shares than the initial 5000.
* When running the script on cluster, the currently user context will be used to for PAPI access.

## Authors
* Andrew Chung

## License
This project is licensed under the MIT License - see the LICENSE.md file for details
