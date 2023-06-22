# `smbclient` Command Line Tool
Used to interact with Samba programs on Linux. [SMB](/networking/protocols/SMB.md) is a network protocol which allows file and printer sharing among computers.

It's normally found on ports 445 or 139.

## Usage: 
```
smbclient [OPTIONS] service <password>
```
### Example:



## Useful options:
- `smbclient -L`
	- gets a list of available SMB shares on the host
	- syntax: ``smbclient -L [HOST IP]``
- `-U`
	- Login identity to use
	- ex: `smbclient -L {target IP} -U Administrator`
	- *HINT:* you can try entering a blank password when prompted while using `Administrator` as the user.
- `smbclient//fileserver/Backup
		- To access the SMB server of a specific SMB share
		- syntax: ``smbclient\\\\IPADDRESS\\ShareName``
- Once in the SMB server shell
	- ``ls``
	- ``cd`` 
	- ``get [filename]`` 
		- downloads file to home directory
		- syntax: ``<REMOTE_FILE_PATH>/<REMOTE_FILE_NAME> <LOCAL_FILE_PATH>/<LOCAL_FILE_NAME>``
			- (tells get where to put downloaded file)

> [!related]
 [SMB](/networking/protocols/SMB.md)
