
## Usage: 
```
smbclient [OPTIONS] service <password>
```

## Useful options:
	#smbclient-L
		- gets a list of available #smb-shares  on the host
		- syntax: ``smbclient -L [HOST IP]``
	- #smbclient//fileserver/Backup
		- To access the #smb-server of a specific #smb-share
		- syntax: ``smbclient\\\\IPADDRESS\\ShareName``
- Once in the #smb-server shell
	- ``ls``
	- ``cd`` 
	- ``get [filename]`` 
		- downloads file to home directory
		- syntax: ``<REMOTE_FILE_PATH>/<REMOTE_FILE_NAME> <LOCAL_FILE_PATH>/<LOCAL_FILE_NAME>``
			- (tells get where to put downloaded file)

>[!related]
[[SMB]]
