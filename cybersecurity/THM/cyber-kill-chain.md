
# Cyber Kill Chain
Historically a military concept r/t the structure of an attack. Now the #cyber-kill-chain-framework, developed by Lockheed Martin, has been established for the cybersecurity industry.
*Does not cover #insider-threats*
- From people who use their authorizatiion inside a system to access/ harm a network system

## Phases:
#### Reconnaissance / #recon: 
Discovering and collecting information on a target in order to craft a method of attack.
1. Attackers perform a lot of #OSINT research into their target in order to discover vulnerabilities, patterns, etc.
2. ex of OSINT:
	1. #email-harvesting : obtaining email addresses from public/ free services
		1. #theHarvester: tool which can be used to harvest emails, as well as domains, sub domains, names, IP addresses, URLs etc.
		2. #Hunter/io
	2. #OSINT-framework 

#### Weaponization / #weaponization 
Combining an #exploit and #malware into a deliverable #payload 

#### Delivery
1. How the weapon gets delivered
2. ex:
	1. [[watering-hole]]
	2. #phishing 
	3. [[candy-drop]]

#### Exploitation
1. when the attacker uses a vulnerability in a device/ system to gain access to the target system
2. Ex of exploits:
	1. a victim triggers the exploit by opening an email attachment/ clicking on a malicious link
	2. [[zero-day]]
	3. vulnerabilities in software/ hardware or even human
	4. server-based vulnerabilities

#### Installation
1. Once an attacker is in, they need to install something to establish persistance (a way to gain access again)
2. a #backdoor is a way for an attacker to establish a way back into the system while bypassing security measures.
	1. also called an #access-point
	2. a #persistent-backdoor allows an attacker to re-access a system they compromised in the past
3. Persistence can be achieved through:
	1. installing a #web-shell on a web server
		1. a malicious script written in web-languages like #PHP and #JavaScript which allows the attacker to maintain access.
		2. usually web sehlles have simplistic file formatting w/ file extensions that are difficult to detect (.php, .asp, .jsp, etc.)
			1. might be classified as "benign"
	2. installing a backdoor on a victim's machine
		1. #Meterpreter can be used to install a backdoor
			1. a [[metasploit]] payload which gives the user an interactive shell which allows interaction with the victim's machine which can remotely execute malicious code
	3. creating or modifying a Windows service
		1. attacker creates or modifies a Windows service to execute malicisou scripts/ payloads
			1. can use #sc/exe and #Reg to modify service configurations
			2. attacker can also #masquerade a payload by using serice names which are known to be r/t the #OS or legitamate software.
	4. Adding the entry to the #run-keys of the malicious payload to the #Registry or #startup-folder.
		1. the payload will execute each time the user logs into the computer
	5. #timestomping
		1. a technique used by attackers to acoid forensic detection.
			1. Also helps make the malware appear legitamate
			2. allows the attacker to modify file #timestamps, including modify, access, create, and change times

#### Command and Control/ #C2 
1. Allows for remote control/ manipulation of the victim
	1. compromised victim/ endpoint communicates to an external sever set up by the attacker
2. #C2-beaconing
3. The C2 infrastructure may be owned by the attacker *but also another compromised host*
4. ex:
	- #IRC (Internet Relay Chat)
		- used to be common for C2 communication but is now easily detected
	- #HTTP on #port-80 OR #HTTPS on #port-443
		- much more common
		- allows attacker to blend malicious traffic w/ legitamate traffic
		- helps them evade #firewalls
	- #DNS 
		- Attacker purchase/ registers a DNS server
		- infected machine makes DNS requests to the malicious DNS server
		- also called #DNS-tunneling

#### Exfiltration/ #exfiltration
1. ex: collecting user credentials, privilege escalation, internal recon, lateral movement thru network, collecting sensitive data, deleting backup/ #shadow-copies 
	1. a Shadow Copy is a microsoft tehcnology which creates backup copies, snapshots, etc of computer files and volumes
2. ovewrwrite of #corrupt data
