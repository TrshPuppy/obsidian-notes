---
aliases: [THM, try-hack-me]
---

# Introductory Networking
1. [[OSI-reference-model]]
	1. [[application-layer]]
	2. "translation services"
	3. [[presentation-layer]]
	4. [[physical-layer]]
		1. binary --> electrical 
		2. electrical --> binary
	5. [[data-link-layer]]
		1. #network-card 
		2. [[MAC-addresses]]
	6. [[network-layer]]
		1. #IPV4 
		2. #IP-address 
		3. Addressing
		4. TCP
			1. #segment
		5. UDP
			1. #datagram
	7. ==layer protocols==
2. #encapsulation 
3. #TCP/IP 
4. Networking Tools:
	1. Ping:
		1. [[ping]]
	2. Traceroute:
		1. [[traceroute]]
	3. WHOIS
		1. [[whois]]
	4. Dig
		1. [[dig]]
		2. [[DNS]] 
5. Further reading:
	1. https://www.amazon.co.uk/Interconnecting-Cisco-Network-Devices-ICND1/dp/1587054620/ref=sr_1_1?keywords=Interconnecting+Cisco+Network+Devices%2C+Part+1&qid=1583683766&sr=8-1

# What is Networking:
1.[[network-fundamentals]]

# Local Area Network Technologies
1. [[LAN]]
2. 


# Pyramid of Pain
[[pyramid-of-pain]] 
1. [[hashing]]
	1. #MD5
	2. #SHA-1 
	3. #SHA-2 
	4. [[DIFR-Report]]
	5. [[FireEye-Threat-Research]]
	6. [[Virus-Total]] 
	7. [[OPSWAT]]  
	8. [[Cyber-Chef]]
	9. [[conti]]
2. #IP-addresses 
	1. [[Akamai]]
	2. [[Fast-Flux]]
	3. [[ASN]] 
	4. [[dig]]
	5. [[curL]]
	6. #curl-I 
	7. #curl-L 
3. #domain-names
	1. #sub-domain
	2. #top-level-domain
	3. [[DNS]]
	4. [[punycode]]
	5. [[URL-shorteners]]
4. #host-artifacts
	1. #IOC 
	2. #user-agent-string 
	3. [[emotet]]
	4. 
5. #network-artifacts
6. [[TTPS]]
	1. [[Mitre-attack-matrix]]
	2. #APT
	3. [[Chimera]]
	4. [[cobalt-strike]]
	5. #muling
	6. [[APT-40]]
	7. #dev/stg

# Junior Sec Analyst Intro
1. [[SOC-analyst]] 
2. [[CISA]]

# Cyber Kill Chain
1. [[cyber-kill-chain]] 
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
				3. [[candy-drop]]
			2. #C2 
			3. #backdoor
			4. [[watering-hole]]
			5. reflections on trusting trust thompson
			6. TCM trusted computing base, trusted execution model

# Metasploit
- #singles
- #stagers
- [[metasploit]]
- #stages
- [[eternal-blue]]
	- #SMB  

# Nmap/ [[nmap]] 
- #Syn-Scan
- #UDP-scan
- #TCP-scan
- #NULL-scan
- #FIN-scan
- #Xmas-scan
- output
- ports
- scripts
	- vuln scripts
- #TCP/IP 
	- https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Protocol_operation
	- #3-way-handshake 
- #UDP
	- https://en.wikipedia.org/wiki/User_Datagram_Protocol#Comparison_of_UDP_and_TCP


my first targets on a machine: ~/.${SHELL}rc, ~/.${SHELL}_profile, ~/.${SHELL}_logout, ~/.${SHELL}_history, ~/.ssh and ~/.aws and a such. I really love IDE scratch files as well.

~/.bashrc for example, if $SHELL is bash, ~/.bashrc is gonna tell you about the user environment. Code monkeys often will hard code secrets in there

~/.aws and ~/.ssh are good for secrets to connect to other systems