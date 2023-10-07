
# Blue Walkthrough
## Recon
Our first nmap scan gives us a few ports and some OS versioning:
```bash
nmap -Pn $t 
	Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-04 13:59 EDT
	Nmap scan report for 10.0.2.6
	Host is up (0.00077s latency).
	Not shown: 991 closed tcp ports (conn-refused)
	PORT      STATE SERVICE
	135/tcp   open  msrpc
	139/tcp   open  netbios-ssn
	445/tcp   open  microsoft-ds
	49152/tcp open  unknown
	49153/tcp open  unknown
	49154/tcp open  unknown
	49155/tcp open  unknown
	49156/tcp open  unknown
	49158/tcp open  unknown
# ---
sudo nmap -A -p 139, 445 $t
	Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-04 14:16 EDT
	Nmap scan report for 10.0.2.6
	Host is up (0.00038s latency).
		PORT    STATE SERVICE     VERSION                        
	139/tcp open  netbios-ssn Windows 7 Ultimate 7601 Service Pack 1 netbios-ssn
...
```
The useful service version we get out of this is `Windows 7 Ultimate 7601 Service Pack 1`.
### [searchsploit](cybersecurity/tools/exploitation/searchsploit.md)
Using searchsploit, we don't find anything about this service version:
```bash
searchsploit 'Microsoft 7 Ultimate'
Exploits: No Results
Shellcodes: No Results
```
### Google
Searching `microsoft 7 ultimate exploits` online, we find a lot of mentions to [EternalBlue](cybersecurity/vulnerabilities/eternalblue.md) and *MS17-010*. EternalBlue is an exploit which uses [SMB](networking/protocols/SMB.md) to get remote code execution on the target. 

We also find the [Exploit DB](cybersecurity/tools/exploitation/exploit-db.md) entry [for EternalBlue](https://www.exploit-db.com/exploits/42315).
## [Metasploit](cybersecurity/tools/metasploit.md)
Now that we've found an exploit that will likely work on this machine, let's see what Metasploit has to help us.


