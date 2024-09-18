
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
Gets a list of available SMB shares on the host
```bash
smbclient -L <target IP>
```
### Accessing shares
To access the SMB server of a specific SMB share the syntax is:
```bash
smbclient ////<target IP>//<share name>
# OR
smbclient //<target IP>/<share name>
```
### Logging in as a user
```bash
smbclient //<target IP>/<target share> -U <username> 
# OR
smbclient <username>@<target IP>
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
