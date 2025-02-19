
# SMB Enumeration
[SMB](../../networking/protocols/SMB.md) is a network protocol primarily used on Windows computers (although Linux has a comparable protocol referred to as [Samba](../../networking/protocols/SMB.md#Samba). SMB uses [TCP](../../networking/protocols/TCP.md) to talk to other computers on a network, mainly for the purposes of sharing files and printing services. It listens on TCP port `445`.

Because SMB has a complex implementation, it has a reputation of poor security and a long history of vulnerabilities (such as [SMB null shares](../../cybersecurity/vulnerabilities/SMB-null-share.md)) and exploits (like [EternalBlue](../../cybersecurity/vulnerabilities/EternalBlue.md)). Because of this, SMB has been improved and updated with each new Windows release.
## NetBIOS
[NetBIOS](../../networking/protocols/NetBIOS.md) is a service which listens on TCP port `139`, as well as some [UDP](../../networking/protocols/UDP.md) ports. Although SMB and NetBIOS are seperate protocols, they're *often enabled together* because older implementations of SMB require *NetBIOS over TCP* (NBT). So, even though newer versions of SMB don't need it, it's usually required in order to be backwards compatible w/ systems running older versions of SMB.

Since they're usually enabled together, enumerating SMB goes hand-in-hand w/ enumerating NetBIOS.
### Scanning with Nmap
To scan SMB and NetBIOS on a target system, you can use the following [nmap](../../CLI-tools/linux/remote/nmap.md) command:
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
### Scanning with `nbtscan`
