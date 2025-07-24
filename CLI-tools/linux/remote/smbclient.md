
# `smbclient` Command Line Tool
Used to interact with Samba programs on Linux. [SMB](/networking/protocols/SMB.md) is a network protocol which allows file and printer sharing among computers. It's normally found on ports 445 or 139.
## Usage: 
```
smbclient [OPTIONS] service <password>
```
**HINT**: Try `//target/` instead of `////target//` - <3 clayhax
> [!HINT]
> 1. Try `//target/` instead of `////target//` - <3 clayhax
> 2. If there are multiple SMB services running on a target, you can specify a port to `smbclient` using `-p`
### Listing shares
Gets a list of available SMB shares on the host, list shares w/ `-L`
```bash
# smbclient -L //172.16.176.10/ --user='MEDTECH/joe'
Password for [MEDTECH\joe]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share
	SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 172.16.176.10 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
### Accessing shares:
To access the SMB server of a specific SMB share, make sure you *include the domain name and the share* (domain name goes into `--user`, share goes w/ the IP address):
```bash
# smbclient //172.16.176.10/C$ --user='MEDTECH/joe' --password='Flowers1'
Try "help" to get a list of possible commands.
smb: \> ls
  $Recycle.Bin                      DHS        0  Thu Oct  6 02:44:47 2022
  $WinREAgent                        DH        0  Wed Jun  1 14:57:15 2022
  Config.Msi                        DHS        0  Tue Nov 29 10:30:45 2022
  Documents and Settings          DHSrn        0  Wed Jun  1 14:10:08 2022
  DumpStack.log.tmp                 AHS    12288  Tue Jul 23 22:22:36 2024
  output.txt                          A     2698  Thu Jun 26 14:08:01 2025
  pagefile.sys                      AHS 738197504  Tue Jul 23 22:22:35 2024
  PerfLogs                            D        0  Sat May  8 01:20:24 2021
  Program Files                      DR        0  Tue Nov 29 10:29:47 2022
  Program Files (x86)                 D        0  Sat May  8 02:39:35 2021
  ProgramData                       DHn        0  Wed Oct  5 10:09:08 2022
  Recovery                         DHSn        0  Wed Jun  1 14:10:11 2022
  System Volume Information         DHS        0  Tue Sep 27 11:33:07 2022
  Users                              DR        0  Thu Oct  6 02:44:32 2022
  Windows                             D        0  Tue Nov 29 10:37:57 2022

		7699967 blocks of size 4096. 4504240 blocks available
smb: \>
```
*HINT:* you can try entering a blank password when prompted while using `anonymous` as the user.
### Listing *Null Shares*
```bash
smbclient -N -L \\\\X.X.X.X
```
### SMB Shell
Once you've gained access to the SMB server on the target, you're given a shell instance.
#### Shell commands
``ls``: list shares/ directories
``cd`` : change directory
`get [filename]`: downloads file to *your* home directory, syntax:
```smb
<REMOTE_FILE_PATH>/<REMOTE_FILE_NAME> <LOCAL_FILE_PATH>/<LOCAL_FILE_NAME>
```

> [!Resources]
> - `man smbclient`
> - [Steflan-Security: SMB Enumeration](https://steflan-security.com/smb-enumeration-guide/)

> [!Related]
> - [SMB protocol](/networking/protocols/SMB.md)
