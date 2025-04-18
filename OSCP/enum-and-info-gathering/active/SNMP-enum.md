
# Enumerating SNMP
[SNMP](../../../networking/protocols/SNMP.md) is a [UDP](../../../networking/protocols/UDP.md) based networking protocol. Newer versions are not as insecure, but the insecure versions (SNMPv1 and v2) are very insecure because their traffic is unencrypted and authentication is based on shared *community strings*. Additionally, on Windows computers, the SNMP Managment Information Base (MIB) database is used to store information *beyond network-based information*. For example, the following table shows MIB values specific to the Microsoft Windows implementation of SNMP:

| MIB Value              | Type of Information Stored |
| ---------------------- | -------------------------- |
| 1.3.6.1.2.1.25.1.6.0   | System Processes           |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs           |
| 1.3.6.1.2.1.25.4.2.1.4 | Processes Path             |
| 1.3.6.1.2.1.25.2.3.1.4 | Storage Units              |
| 1.3.6.1.2.1.25.6.3.1.2 | Software Name              |
| 1.3.6.1.4.1.77.1.2.25  | User Accounts              |
| 1.3.6.1.2.1.6.13.1.3   | TCP Local Ports            |
## Enumerating
SNMP is usually listening on UDP `port 161`, so the following [nmap](../../../CLI-tools/linux/remote/nmap.md) command can be used to find open SNMP services on a target host:
```bash
sudo nmap -sU --open -p 161 <target IP> -oG open-snmp.txt
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-14 06:02 EDT
Nmap scan report for 192.168.50.151
Host is up (0.10s latency).

PORT    STATE SERVICE
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds
...
```
## Brute Forcing Community Strings
SNMPv1 and v2 use community strings for authentication. Community strings are just sing strings which networking devices have to supply in order to request to see another device's statistics/ info using SNMP. 

Not only can these strings be *intercepted* (since they're transmitted in plaintext), many network administrators fail to configure SNMP with unique community strings. This means their SNMP devices are using default SNMP strings like "public", "private", and "manager."
### onesixtyone
`onesixtyone` is a tool which will attempt to brute force an IP address using a list of community strings supplied to it. We can give it a list of IP addresses to brute force against as well:
```bash
kali@kali:~$ echo public > community
kali@kali:~$ echo private >> community
kali@kali:~$ echo manager >> community

kali@kali:~$ for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips

kali@kali:~$ onesixtyone -c community -i ips
Scanning 254 hosts, 3 communities
192.168.50.151 [public] Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)
...
```
- `-c` our file of community strings
- `-i` our file of IP addresses
Once we have a list of hosts with SNMP services configured with the read-only community strings from our list, we can use another tool called `snmpwalk` to probe each host for information.
### snmpwalk
To use `snmpwalk` we have to provide it with the community string and the host we want to scan.  `snmpwalk` will use the community string to enumerate *the entire MIB tree* for us and print the output. 
```bash
kali@kali:~$ snmpwalk -c public -v1 -t 10 192.168.50.151
iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.311.1.1.3.1.3
iso.3.6.1.2.1.1.3.0 = Timeticks: (78235) 0:13:02.35
iso.3.6.1.2.1.1.4.0 = STRING: "admin@megacorptwo.com"
iso.3.6.1.2.1.1.5.0 = STRING: "dc01.megacorptwo.com"
iso.3.6.1.2.1.1.6.0 = ""
iso.3.6.1.2.1.1.7.0 = INTEGER: 79
iso.3.6.1.2.1.2.1.0 = INTEGER: 24
...
```
- `-v1` tells `snmpwalk` which version of SNMP the target host is using
- `-c` is the community string we want it to use
- `-t` tells `snmpwalk` to increase the timeout period (by 10 seconds in this case)
#### Parsing specific MIB branch
`snmpwalk` can also parse specific branches of the tree. For example, here is how you would parse the OID sub branch of a MIB tree of a Windows host (the OID subtree is usually holds information about local user accounts on the machine or [domain controller](../../../computers/windows/active-directory/domain-controller.md)):
```bash
kali@kali:~$ snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25
iso.3.6.1.4.1.77.1.2.25.1.1.5.71.117.101.115.116 = STRING: "Guest"
iso.3.6.1.4.1.77.1.2.25.1.1.6.107.114.98.116.103.116 = STRING: "krbtgt"
iso.3.6.1.4.1.77.1.2.25.1.1.7.115.116.117.100.101.110.116 = STRING: "student"
iso.3.6.1.4.1.77.1.2.25.1.1.13.65.100.109.105.110.105.115.116.114.97.116.111.114 = STRING: "Administrator"
```
##### `1.3.6.1.2.1.25.4.2.1.2`- Currently running processes
```bash
kali@kali:~$ snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2
iso.3.6.1.2.1.25.4.2.1.2.1 = STRING: "System Idle Process"
iso.3.6.1.2.1.25.4.2.1.2.4 = STRING: "System"
iso.3.6.1.2.1.25.4.2.1.2.88 = STRING: "Registry"
iso.3.6.1.2.1.25.4.2.1.2.260 = STRING: "smss.exe"
iso.3.6.1.2.1.25.4.2.1.2.316 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.372 = STRING: "csrss.exe"
iso.3.6.1.2.1.25.4.2.1.2.472 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.476 = STRING: "wininit.exe"
iso.3.6.1.2.1.25.4.2.1.2.484 = STRING: "csrss.exe"
iso.3.6.1.2.1.25.4.2.1.2.540 = STRING: "winlogon.exe"
iso.3.6.1.2.1.25.4.2.1.2.616 = STRING: "services.exe"
iso.3.6.1.2.1.25.4.2.1.2.632 = STRING: "lsass.exe"
iso.3.6.1.2.1.25.4.2.1.2.680 = STRING: "svchost.exe"
...
```
##### `1.3.6.1.2.1.25.6.3.1.2`  - All currently installed software  
```bash
kali@kali:~$ snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.6.3.1.2
iso.3.6.1.2.1.25.6.3.1.2.1 = STRING: "Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.27.29016"
iso.3.6.1.2.1.25.6.3.1.2.2 = STRING: "VMware Tools"
iso.3.6.1.2.1.25.6.3.1.2.3 = STRING: "Microsoft Visual C++ 2019 X64 Additional Runtime - 14.27.29016"
iso.3.6.1.2.1.25.6.3.1.2.4 = STRING: "Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.27.290"
iso.3.6.1.2.1.25.6.3.1.2.5 = STRING: "Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.27.290"
iso.3.6.1.2.1.25.6.3.1.2.6 = STRING: "Microsoft Visual C++ 2019 X86 Additional Runtime - 14.27.29016"
iso.3.6.1.2.1.25.6.3.1.2.7 = STRING: "Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.27.29016"
...
```
##### `1.3.6.1.2.1.6.13.1.3`- All currently listening TCP ports
```bash
kali@kali:~$ snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.6.13.1.3
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.88.0.0.0.0.0 = INTEGER: 88
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.135.0.0.0.0.0 = INTEGER: 135
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.389.0.0.0.0.0 = INTEGER: 389
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.445.0.0.0.0.0 = INTEGER: 445
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.464.0.0.0.0.0 = INTEGER: 464
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.593.0.0.0.0.0 = INTEGER: 593
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.636.0.0.0.0.0 = INTEGER: 636
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.3268.0.0.0.0.0 = INTEGER: 3268
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.3269.0.0.0.0.0 = INTEGER: 3269
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.5357.0.0.0.0.0 = INTEGER: 5357
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.5985.0.0.0.0.0 = INTEGER: 5985
...
```
Each `INTEGER` value represents the local TCP port which is currently listening for incoming connections on the host. This can reveal *even more services* which may not be listed through the other MIB branches.
### Converting hexadecimal values
```bash
┌─[25-03-14 21:13:40]:(root@192.168.144.131)-[/home/trshpuppy/oscp/recon]
└─# snmpwalk -c public -v1 -t 10 192.168.197.151
iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: AMD64 Family 23 Model 1 Stepping 2 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.311.1.1.3.1.3
iso.3.6.1.2.1.1.3.0 = Timeticks: (107723644) 12 days, 11:13:56.44
iso.3.6.1.2.1.1.4.0 = STRING: "admin@megacorptwo.com"
iso.3.6.1.2.1.1.5.0 = STRING: "dc01.megacorptwo.com"
iso.3.6.1.2.1.1.6.0 = ""
iso.3.6.1.2.1.1.7.0 = INTEGER: 79

..snip..

iso.3.6.1.2.1.2.2.1.1.24 = INTEGER: 24
iso.3.6.1.2.1.2.2.1.2.1 = Hex-STRING: 53 6F 66 74 77 61 72 65 20 4C 6F 6F 70 62 61 63
6B 20 49 6E 74 65 72 66 61 63 65 20 31 00 # Hex value
...
```
If we give `snmpwalk` the `-Oa` flag, it will convert any hexadecimal values to ASCII:
```bash
┌─[25-03-14 21:11:43]:(root@192.168.144.131)-[/home/trshpuppy/oscp/recon]
└─# snmpwalk -c public -v1 -t 10 192.168.197.151 -Oa
iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: AMD64 Family 23 Model 1 Stepping 2 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.311.1.1.3.1.3
iso.3.6.1.2.1.1.3.0 = Timeticks: (107705227) 12 days, 11:10:52.27
iso.3.6.1.2.1.1.4.0 = STRING: "admin@megacorptwo.com"
iso.3.6.1.2.1.1.5.0 = STRING: "dc01.megacorptwo.com"
iso.3.6.1.2.1.1.6.0 = ""
iso.3.6.1.2.1.1.7.0 = INTEGER: 79

..snip..

iso.3.6.1.2.1.2.2.1.1.24 = INTEGER: 24 
iso.3.6.1.2.1.2.2.1.2.1 = STRING: "Software Loopback Interface 1." # Converted
...
```

> [!Resources]
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.