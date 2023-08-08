
# [Kioptrix](https://www.vulnhub.com/series/kioptrix,8/)
Kioptrix is a vulnerable VM you can download from [VulnHub](https://www.vulnhub.com). There are multiple [walkthroughs]() for attacking this box. The following are my notes from my own Kioptrix campaign:
## 1. [Scanning w/ nmap](/nested-repos/PNPT-study-guide/practical-ethical-hacking/scanning-enumeration/scanning-with-nmap.md)
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
#### Architecture:
From this scan we learn some things about the target's architecture:
1. The server supports OpenSSHv1 and we have some exposed host-keys (used to authenticate during an [SSH](/networking/protocols/SSH.md) connection)
2. Ports 80 and 443 ([HTTP](/networking/protocols/HTTP.md) & [HTTPS](/networking/protocols/HTTPS.md)) are running an Apache server, v1.3.20 as well as OpenSSL

**NOTE:** Any information about the software being used by the target, and the software's versions, is considered a finding because it can be used by an attacker to find exploits/ CVE's related to that software and its version.

#### Other Services:
3. Port 111 is running [RPC](/networking/protocols/RPC.md) (Remote Procedure Call)



> [!Resources]
> - [hummus-ful: Kioptrix Walkthrough](https://hummus-ful.github.io/vulnhub/2021/01/17/Kioptrix_1.html)
> -  [VulnHub](https://www.vulnhub.com)

> [!My previous notes (linked in text)]
> - [SSH](https://github.com/TrshPuppy/obsidian-notes/tree/main/networking/protocols/SSH.md) 
> - [HTTP](https://github.com/TrshPuppy/obsidian-notes/tree/main/networking/protocols/HTTP.md)
> - [HTTPS](https://github.com/TrshPuppy/obsidian-notes/tree/main/networking/protocols/HTTPS.md)
