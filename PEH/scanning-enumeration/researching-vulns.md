
# Researching Potential Vulnerabilities
Based on what we've found in our scanning and enumeration of Kioptrix, we need to research the vulnerabilities we may have identified.
## The Findings
Ranked in order of what we feel would be the easiest to exploit and/ or most vulnerable:
```bash
Target: 10.0.3.5
Ports w/ findings:
	80: HTTP
		:80/
			Default page for Apache Web Server:
				Apache v1.3.20 (Unix) (Red-Hat/Linux)
				mod_ssl v2.8.4
		:80/manual/*
			manual pages for Apache HTTP Server Version 1.3b5
		:80/manual/mod/mod_ssl/*
			manual pages for mod_ssl v2.8.31
	443: HTTPS
			Apache/1.3.20 (Unix)  (Red-Hat/Linux) 
				mod_ssl v2.8.4 
				OpenSSL v0.9.6b
				SSLv2 supported
	139: Samba/ NetBIOS
		workgroup: MYGROUP
		Anonymous login allowed (no password)
		Shares:
			IPC$
			ADMIN$
		SMB version 2.2.1a
		ntlmv2
	445: 
	22: OpenSSH
```
## Starting w/ `mod_ssl`
The version we've found using nmap is `2.8.4`. Using that, we can search for vulnerabilities/ exploits r/t this exact version. There are a few resources we can use to do this.
### [Exploit DB](/cybersecurity/tools/reverse-engineering/exploit-db.md):
Exploit DB is a database of malware. The malware can be perused [online](https://www.exploit-db.com/exploits/764) or downloaded into a VM and looked through/ used that way. *When downloading, malware should be downloaded into an isolated environment* b/c it will carry out its designed actions when executed.

Exploit DB can also be searched via the command line using the [searchsploit](/cybersecurity/tools/reverse-engineering/searchsploit.md) command.
```bash
searchsploit mod_ssl 2.8.4
Exploit Title                                               |  Path
--------------------------------------------------------------------------------------
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow                                                                              | unix/remote/21671.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (1)                                                                        | unix/remote/764.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)                                                                        | unix/remote/47080.c
--------------------------------------------------------------------------------------
Shellcodes: No Results
```
Using either the online database, or `searchsploit`, we find [`OpenFuck`](/cybersecurity/vulnerabilities/openfuck.md) which is a remote [buffer overflow](/cybersecurity/TTPs/exploitation/buffer-overflow.md). From the online database, you can review the code of the exploit itself:
![](nested-repos/PNPT-study-guide/PNPT-pics/researching-vulns-1.png)
> [Exploit DB: OpenFuckV2.c](https://www.exploit-db.com/exploits/764)
