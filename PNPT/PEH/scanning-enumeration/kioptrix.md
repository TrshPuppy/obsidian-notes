
# [Kioptrix](https://www.vulnhub.com/series/kioptrix,8/)
Kioptrix is a vulnerable VM you can download from [VulnHub](https://www.vulnhub.com). There are multiple [walkthroughs]() for attacking this box. The following are my notes from my own Kioptrix campaign:
## 1. [Scanning w/ nmap](/PNPT/PEH/scanning-enumeration/scanning-with-nmap.md)
`kioptrix_nmap.txt`:
```bash
sudo nmap -A -p- 10.0.3.5
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-05 18:15 EDT
Nmap scan report for 10.0.3.5
Host is up (0.00068s latency).
Not shown: 65529 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 2.9p2 (protocol 1.99)
|_sshv1: Server supports SSHv1
| ssh-hostkey: 
|   1024 x:x:x:x:x:x:x:x:x:x:x:x:x:x:x:x (RSA1)
|   1024 x:x:x:x:x:x:x:x:x:x:x:x:x:x:x:x (DSA)
|_  1024 x:x:x:x:x:x:x:x:x:x:x:x:x:x:x:x (RSA)
80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Test Page for the Apache Web Server on Red Hat Linux
111/tcp   open  rpcbind     2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1          32768/tcp   status
|_  100024  1          32768/udp   status
139/tcp   open  netbios-ssn Samba smbd (workgroup: MYGROUP)
443/tcp   open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5                                   
|     SSL2_RC2_128_CBC_WITH_MD5                                     
|     SSL2_DES_192_EDE3_CBC_WITH_MD5                                   
|     SSL2_RC4_64_WITH_MD5                                          
|_    SSL2_RC4_128_WITH_MD5                                           
|_http-title: 400 Bad Request                                          
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--            
| Not valid before: 2009-09-26T09:32:06                               
|_Not valid after:  2010-09-26T09:32:06                                
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b                                                                 
|_ssl-date: 2023-08-06T02:16:28+00:00; +3h59m59s from scanner time.    
32768/tcp open  status      1 (RPC #100024)
MAC Address: x:x:x:x:x:x (Oracle VirtualBox virtual NIC)          
Device type: general purpose                                           
Running: Linux 2.4.X                              
OS CPE: cpe:/o:linux:linux_kernel:2.4                               
OS details: Linux 2.4.9 - 2.4.18 (likely embedded)                      
Network Distance: 1 hop

Host script results:                                                     
|_nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)                                            
|_smb2-time: Protocol negotiation failed (SMB2)                  
|_clock-skew: 3h59m58s                                                           

TRACEROUTE
HOP RTT     ADDRESS
1   0.68 ms 10.0.3.5

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.16 seconds
```
### Findings (nmap):
#### Web Architecture:
From this scan we learn some things about the target's architecture:
1. The server supports OpenSSHv1 and we have some exposed host-keys (used to authenticate during an [SSH](/networking/protocols/SSH.md) connection)
2. Ports 80 and 443 ([HTTP](/www/HTTP.md) & [HTTPS](/www/HTTPS.md)) are running an Apache server, v1.3.20 as well as OpenSSL

**NOTE:** Any information about the software being used by the target, and the software's versions, is considered a finding because it can be used by an attacker to find exploits/ CVE's related to that software and its version.
##### Open[SSL](/networking/protocols/SSL.md)
On port 443 (HTTPS) we can see OpenSSL is being used (and an old version) to authenticate and encrypt the target's web-data/ traffic.
#### Port & Service Mapping:
##### RPC:
Port 111 is running [RPC](/networking/protocols/RPC.md) (Remote Procedure Call). `nmap` also tells us that the *program numbers* of the programs using the RPC protocol, as well as the ports they're on. 

We can use this to probe those ports and see what type of information we get back. For example, using the [rpcinfo](/CLI-tools/linux/rpcbind-rpcinfo.md) command w/ the port `32768` we can get slightly more info back:
```bash
rpcinfo -s -n 32768 10.0.3.5
   program version(s) netid(s)                         service     owner
    100000  2         udp,tcp                          portmapper  unknown
    100024  1         tcp,udp                          status      unknown
```
## 2. Vulnerability Scanning w/ [Nikto](/cybersecurity/tools/scanning-enumeration/vuln-scanning/nikto.md)
`kioptrix_nikto.txt`:
```bash
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.0.3.5
+ Target Hostname:    10.0.3.5
+ Target Port:        80
+ Start Time:         2023-08-05 18:39:31 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
+ /: Server may leak inodes via ETags, header found with file /, inode: 34821, size: 2890, mtime: Wed Sep  5 23:12:46 2001. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Apache is vulnerable to XSS via the Expect header. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3918
+ Apache/1.3.20 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OpenSSL/0.9.6b appears to be outdated (current is at least 3.0.7). OpenSSL 1.1.1s is current for the 1.x branch and will be supported until Nov 11 2023.
+ mod_ssl/2.8.4 appears to be outdated (current is at least 2.9.6) (may depend on server version).
+ Apache/1.3.20 - Apache 1.x up 1.2.34 are vulnerable to a remote DoS and possible code execution.
+ Apache/1.3.20 - Apache 1.3 below 1.3.27 are vulnerable to a local buffer overflow which allows attackers to kill any process on the system.
+ Apache/1.3.20 - Apache 1.3 below 1.3.29 are vulnerable to overflows in mod_rewrite and mod_cgi.
+ mod_ssl/2.8.4 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell.
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, OPTIONS, TRACE .
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ ///etc/hosts: The server install allows reading of any system file by adding an extra '/' to the URL.
+ /usage/: Webalizer may be installed. Versions lower than 2.01-09 vulnerable to Cross Site Scripting (XSS). See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2001-0835
+ /manual/: Directory indexing found.
+ /manual/: Web server manual found.
+ /icons/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /test.php: This might be interesting.
+ /wp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wordpress/wp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wordpress/wp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.                                                 
+ /wordpress/wp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.                      
+ /assets/mobirise/css/meta.php?filesrc=: A PHP backdoor file manager was found: 
+ /login.cgi?cli=aa%20aa%27cat%20/etc/hosts: Some D-Link router remote command execution.                                                          
+ /shell?cat+/etc/hosts: A backdoor was identified.
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 8908 requests: 0 error(s) and 30 item(s) reported on remote host
+ End Time:           2023-08-05 18:39:59 (GMT-4) (28 seconds)                   
---------------------------------------------------------------------------      
+ 1 host(s) tested   
```
### Nikto findings:
**NOTE:** Some targets w/ good security/ firewalls will block nikto.
#### Outdated software/ services:
Anything that returns as 'outdated' w/ Nikto can be reported as a finding. The more behind the version in use is to the current released version *the more serious the finding is*.
#### Directory Enumeration:
Nikto shows that there are some possible subdirectories we can enumerate on ports 80 and 443. To check for these, we can run a handful of tools:
##### [Feroxbuster](/cybersecurity/tools/scanning-enumeration/dir-and-subdomain/feroxbuster.md)
Feroxbuster is a tool similar to [gobuster](/cybersecurity/tools/scanning-enumeration/dir-and-subdomain/gobuster.md) except it's able to *do recursive enumeration*. We can try feroxbuster against Kioptrix like this:
```bash
feroxbuster -u http://10.0.3.5
# or:
feroxbuster -u https://10.0.3.5
```
With Kioptrix, we can find a few more instances of *information disclosure*. For example the subdirectory `/manual/mod/mod_perl.html` is a default user's manual for for using perl on the server.

From this page we can see that *the Apache HTTP Server* is version 1.3b5. Another subdirectory we find with feroxbuser is `manual/mod/mod_perl.html`. From this page we can flip through an entire SSL-related module. From here we learn that the server is likely using *Mod_SSL version 2.8.31*.

These information disclosures are nice, but there isn't much else of use reported by feroxbuster and nikto. In fact, some of the subdirectories identified by nikto are *redirects or no longer active*, and we can't do anything with them.





######### POST MORTEM?#####
- metasploit:
	- `exploit/linux/samba/trans2open`
		- buffer overflow
		- **PAYLOAD**
		- `linux/x86/shell/reverse_tcp`
	- Once we in:
		- whoami
		- persistence
			- way back in
			- 
		- history
		- users
		- networking
		- groups
		- passwords
		- services
		- software
		- devices
		- files
		- directories
		- tasty data
		- 
- mail command
- SMB
	- trans2open
	- smbget
	- enum4linux
- openSSL
	- openfuck
- feroxbuster
	- 




> [!Resources]
> - [hummus-ful: Kioptrix Walkthrough](https://hummus-ful.github.io/vulnhub/2021/01/17/Kioptrix_1.html)
> -  [VulnHub](https://www.vulnhub.com)

> [!My previous notes (linked in text)]
> - [SSH](https://github.com/TrshPuppy/obsidian-notes/tree/main/networking/protocols/SSH.md) 
> - [HTTP](https://github.com/TrshPuppy/obsidian-notes/tree/main/networking/protocols/HTTP.md)
> - [HTTPS](https://github.com/TrshPuppy/obsidian-notes/tree/main/networking/protocols/HTTPS.md)
> - [RPC](https://github.com/TrshPuppy/obsidian-notes/tree/main/networking/protocols/RPC.md)
> - [rpcinfo](https://github.com/TrshPuppy/obsidian-notes/tree/main/CLI-tools/linux/rpcbind-rpcinfo.md)
> - [SSL](https://github.com/TrshPuppy/obsidian-notes/tree/main/networking/protocols/SSL.md)
