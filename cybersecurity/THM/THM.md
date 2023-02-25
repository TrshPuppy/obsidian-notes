---
aliases: [THM, try-hack-me]
---
# Introductory Networking
1. [OSI-reference-model](/networking/OSI/OSI-reference-model.md)
2. Networking Tools:
	1. [Ping command](ping.md)
	2. [Traceroute](traceroute.md)
	3. [Who Is Lookup](whois.md)
	4. [Dig](/linux-commands/dig,md)
		2. [DNS](/networking/protocols/DNS.md) 

# What is Networking:
1. [Networking Fundamentals](/cybersecurity/THM/networking-fundamentals.md)

# Local Area Network Technologies
1. [LAN](/networking/routing/LAN.md)

# Phishing Analysis Tools
See: [Phishing](/cybersecurity/attacks/phishing.md) and [Phishing Defense](/cybersecurity/defense/phishing-defense.md)

# Pyramid of Pain
[pyramid-of-pain](/cybersecurity/THM/pyramid-of-pain.md)
1. [hashing](/cybersecurity/hashing.md)
	1. #MD5
	2. #SHA-1 
	3. #SHA-2 
	4. [DIFR-Report](/cybersecurity/literature/DIFR-report.md)
	5. [FireEye-Threat-Research](/cybersecurity/literature/FireEye-Threat-Research.md)
	6. [Virus-Total](/cybersecurity/tools/virus-total.md) 
	7. [OPSWAT](/cybersecurity/tools/OPSWAT.md)  
	8. [Cyber-Chef](/cybersecurity/tools/Cyber-Chef.md)
	9. [Conti Malware](/cybersecurity/malware/conti.md)
2. #IP-addresses 
	1. [Akamai](/cybersecurity/literature/Akamai.md)
	2. [Fast-Flux](cybersecurity/attacks/Fast-Flux.md)
	3. [ASN](/networking/ASN.md) 
	4. [curL](curL.md)
		1. #curl-I 
		2. #curl-L 
3. #domain-names
	1. #sub-domain
	2. #top-level-domain
	3. [DNS](/networking/routing/DNS.md)
	4. [punycode](/cybersecurity/attacks/punycode.md)
	5. [URL-shorteners](/cybersecurity/attacks/URL-shorteners.md)
4. #host-artifacts
	1. #IOC 
	2. #user-agent-string 
	3. [Emotet malware](/cybersecurity/malware/emotet.md)
5. #network-artifacts
6. [TTPS](TTPS.md)
	1. [MITRE-ATT&CK Matrix](/cybersecurity/literature/MITRE-ATT&CK.md)
	2. #APT
	3. [APT-40](APT-40.md)
	4. #dev/stg

# Cyber Kill Chain
1. [Cyber Kill Chain](/cybersecurity/THM/cyber-kill-chain.md)
	1. #reconnaissance
		1. #OSINT
		2. #email-harvesting
	2. #weaponization
		1. #malware 
		2. #exploit
		3. #payload 
		4. #VBA Visual basic application
			1. #macros
				1. ex: docm vs docx (file extention)
				2. macros have to be enabled except in "trueste contexts"
				3. [Candy Drop](/cybersecurity/attacks/candy-drop.md)
			2. #C2 
			3. #backdoor
			4. [Watering Hole Attack](/cybersecurity/attacks/watering-hole.md)

# Metasploit
- #singles
- #stagers
- [Metasploit](/cybersecurity/tools/metasploit.md)
- #stages
	- [SMB](/networking/protocols/SMB.md)

# Nmap/ [[nmap]] 
[Nmap CLI tool](nmap.md)
- #Syn-Scan
- #UDP-scan
- #TCP-scan
- #NULL-scan
- #FIN-scan
- #Xmas-scan
- output
- ports
- scripts
	- vuln script


my first targets on a machine: ~/.${SHELL}rc, ~/.${SHELL}_profile, ~/.${SHELL}_logout, ~/.${SHELL}_history, ~/.ssh and ~/.aws and a such. I really love IDE scratch files as well.

~/.bashrc for example, if $SHELL is bash, ~/.bashrc is gonna tell you about the user environment. Code monkeys often will hard code secrets in there

~/.aws and ~/.ssh are good for secrets to connect to other systems