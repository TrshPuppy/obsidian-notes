
# SMB Enumeration
[SMB](../../../networking/protocols/SMB.md) is a network protocol primarily used on Windows computers (although Linux has a comparable protocol referred to as [Samba](../../../networking/protocols/SMB.md#Samba). SMB uses [TCP](../../../networking/protocols/TCP.md) to talk to other computers on a network, mainly for the purposes of sharing files and printing services. It listens on TCP port `445`.

Because SMB has a complex implementation, it has a reputation of poor security and a long history of vulnerabilities (such as [SMB null shares](../../../cybersecurity/vulnerabilities/SMB-null-share.md)) and exploits (like [EternalBlue](../../../cybersecurity/vulnerabilities/EternalBlue.md)). Because of this, SMB has been improved and updated with each new Windows release.
## NetBIOS
[NetBIOS](../../../networking/protocols/NetBIOS.md) is a service which listens on TCP port `139`, as well as some [UDP](../../../networking/protocols/UDP.md) ports. Although SMB and NetBIOS are seperate protocols, they're *often enabled together* because older implementations of SMB require *NetBIOS over TCP* (NBT). So, even though newer versions of SMB don't need it, it's usually required in order to be backwards compatible w/ systems running older versions of SMB.

Since they're usually enabled together, enumerating SMB goes hand-in-hand w/ enumerating NetBIOS.
## Enumerating with Linux
### Nmap
To scan SMB and NetBIOS on a target system, you can use the following [nmap](../../../CLI-tools/linux/remote/nmap.md) command:
```bash
kali@kali:~$ nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254

kali@kali:~$ cat smb.txt
# Nmap 7.92 scan initiated Thu Mar 17 06:03:12 2022 as: nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254
# Ports scanned: TCP(2;139,445) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 192.168.50.1 ()	Status: Down
...
Host: 192.168.50.21 ()	Status: Up
Host: 192.168.50.21 ()	Ports: 139/closed/tcp//netbios-ssn///, 445/closed/tcp//microsoft-ds///
...
Host: 192.168.50.217 ()	Status: Up
Host: 192.168.50.217 ()	Ports: 139/closed/tcp//netbios-ssn///, 445/closed/tcp//microsoft-ds///
# Nmap done at Thu Mar 17 06:03:18 2022 -- 254 IP addresses (15 hosts up) scanned in 6.17 seconds
```
#### Using Nmap SMB Scripts
Nmap has a lot of [NSE scripts](../../../CLI-tools/linux/remote/nmap.md#Nmap%20Scripting%20Engine) we can use to discover more about and host and its SMB/ NetBIOS services. To find all of the nmap scripts related to SMB, we can list the `/usr/share/nmap/scripts/smb` directory:
```bash
kali@kali:~$ ls -1 /usr/share/nmap/scripts/smb*
/usr/share/nmap/scripts/smb2-capabilities.nse
/usr/share/nmap/scripts/smb2-security-mode.nse
/usr/share/nmap/scripts/smb2-time.nse
/usr/share/nmap/scripts/smb2-vuln-uptime.nse
/usr/share/nmap/scripts/smb-brute.nse
/usr/share/nmap/scripts/smb-double-pulsar-backdoor.nse
/usr/share/nmap/scripts/smb-enum-domains.nse
/usr/share/nmap/scripts/smb-enum-groups.nse
/usr/share/nmap/scripts/smb-enum-processes.nse
/usr/share/nmap/scripts/smb-enum-sessions.nse
/usr/share/nmap/scripts/smb-enum-shares.nse
/usr/share/nmap/scripts/smb-enum-users.nse
/usr/share/nmap/scripts/smb-os-discovery.nse # only works w/ SMBv1
...
```
If we were to scan a Windows target using the `smb-os-discovery` script, our nmap command and output might look like this:
```bash
kali@kali:~$ nmap -v -p 139,445 --script smb-os-discovery 192.168.50.152
...
PORT    STATE SERVICE      REASON
139/tcp open  netbios-ssn  syn-ack
445/tcp open  microsoft-ds syn-ack

Host script results:
| smb-os-discovery:
|   OS: Windows 10 Pro 22000 (Windows 10 Pro 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: client01
|   NetBIOS computer name: CLIENT01\x00
|   Domain name: megacorptwo.com
|   Forest name: megacorptwo.com
|   FQDN: client01.megacorptwo.com
|_  System time: 2022-03-17T11:54:20-07:00
...
```
Note that the script identified the target as running Windows 10 but it is *actually running Windows 11*. Even though both can be inaccurate, doing OS fingerprinting using the NSE creates *less traffic on the target* than using nmap's OS fingerprinting.
### Scanning with `nbtscan`
[`nbtscan`](../../../CLI-tools/linux/nbtscan.md) is a linux command line tool we can use to scan for SMB and Samba services on a host. It is used specifically for identifying NetBIOS information and it does so by *querying the NetBIOS name service* for valid NetBIOS names. We can use the `-r` flag to scan the originating UDP port `137`:
```bash
kali@kali:~$ sudo nbtscan -r 192.168.50.0/24
Doing NBT name scan for addresses from 192.168.50.0/24

IP address       NetBIOS Name     Server    User             MAC address
------------------------------------------------------------------------------
192.168.50.124   SAMBA            <server>  SAMBA            00:00:00:00:00:00
192.168.50.134   SAMBAWEB         <server>  SAMBAWEB         00:00:00:00:00:00
...
```
The scans output shows two hosts and their NetBIOS names `SAMBA` and `SAMBAWEB`. NetBIOS names tend to be very descriptive and can tell us the host's specific role w/i the target network.
## Enumerating with Windows
In a Windows environment we can use the `net view` command to  list domains, resources, and computers belonging to the target host. For example, the following command lists all the *shares* running on a local *[Domain Controller](../../../computers/windows/active-directory/domain-controller.md)* (DC) ("shares" is the term used to refer to *files hosted on an SMB service*).
```powershell
C:\Users\student> net view \\dc01 /all
Shared resources at \\dc01

Share name  Type  Used as  Comment
-------------------------------------------------------------------------------
ADMIN$      Disk           Remote Admin
C$          Disk           Default share
IPC$        IPC            Remote IPC
NETLOGON    Disk           Logon server share
SYSVOL      Disk           Logon server share
The command completed successfully.
```
In this command, `/all` tells `net` to list all of the shares *ending in a dollar sign* (as well as the ones w/o a `$`).

> [!Resources]
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.