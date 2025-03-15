
# xfreerdp
Init
An X11 [RDP](/networking/protocols/RDP.md) client chish (wtf was I trying to write here?) is part of the FreeRDP project. RDP servers are built into many versions of Windows.
## Usage
```
xfreerdp [file] [options] [/v:server[:port]]
```
### Useful options
#### `/u:` 
Set the username to login with:
```bash
xfreerdp /u:<username> /v:<IP address>
```
If you don't set a username it will default to your own username (ex: "hackpuppy");
#### `/v:`
Set the IP/ host to login to
#### `/p:`
Set the password
```bash
xfreerdp /u:<username> /p:<password> /v:<host>
```
## Security
### Vulnerabilities
#### Administrator username
The *administrator* username may not be protected on a host. RDP sometimes can be accessed w/ the admin username and NO PASSWORD.

> [!Resources]
> - `man xfreerdp`