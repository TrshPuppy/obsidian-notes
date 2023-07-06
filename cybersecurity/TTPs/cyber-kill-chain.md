
# Cyber Kill Chain
Historically a military concept r/t the structure of an attack. Now the Cyber Killchain Framework, developed by [Lockheed Martin](https://www.lockheedmartin.com), has been established for the cybersecurity industry.

Operates w/ the assumption that the attacker is outside of the target system. *Does not cover insider-threats* or people who use their authorization inside a system to access/ harm a network system

## Phases:
### Reconnaissance / recon:
Reconnaissance refers to the collection of information on a target using passive/ stealthy means. The information collected can be done from the outside (before the target has been exploited) *and from the inside* (after you've exploited and gained access).

Recon can describe both *passive* and *active* techniques:
- passive: the information is gathered *quietly* without the target knowing
- active: the information is gathered more *aggressively* which may alert the target.

Active techniques can be used to get a better, more accurate profile of the  target *at the risk of alerting them*. These techniques are expected to be done in order.

#### [OSINT](/cybersecurity/TTPs/recon/OSINT.md) (outside the target):
OSINT usually refers to the gathering of *open source* intelligence on a target. Open source means the info is *public* so gathering it should not include any illegal activity (passive recon).

There are some gray areas surrounding whether public info has been gathered legally or illegally depending on the means. For example, it's technically legal to do [subdomain enumeration](/cybersecurity/TTPs/subdomain-enumeration.md) if you were to do it by hand. But running a program against the domain which automates enumeration of its subdomains can be considered illegal.

Most attackers perform a lot of [OSINT](/cybersecurity/TTPs/recon/OSINT.md) research into their target in order to discover vulnerabilities, patterns, etc.. Vulnerabilities can be technological or personal/ human in nature (for example: finding a staff member of a target who's public info can be used against them in a [social-engineering](/cybersecurity/TTPs/social-engineering.md) attack).

##### Examples of OSINT techniques:
- Looking at a target's website and finding what [technologies](/nested-repos/PNPT-study-guide/practical-ethical-hacking/recon/website-tech-recon.md) it uses.
- Looking up a target on google maps
- *Passive* [email harvesting](/cybersecurity/TTPs/recon/email-harvesting.md): obtaining email addresses from public/ free services
		1. [The Harvester](/cybersecurity/tools/recon/the-harvester.md) tool which can be used to harvest emails, as well as domains, sub domains, names, IP addresses, URLs etc.
		2. [Hunter.io](https://hunter.io/email-finder)
- Finding who works for a target using LinkedIn, etc.

#### Recon *once inside the target/system*:
*Note:* this part deviates from the original cyber kill chain.

Recon can also be done once you  have breached the target and have access to the system. After *persistence* has been established, further intelligence should be gathered which can be done quietly.

Especially in [penetration testing](/cybersecurity/penetration-testing.md) the questions once you've breached a system which further recon can answer are:
1. **What can I know** about this target?
2. **What can I do** now that I've breached them?

##### Examples of on-target recon techniques:
- *Groups/Users*: who are you upon entrance? What other groups and users exist? What permissions do they have?
- *Globbing the filesystem*: make a list/map of everything on the system. Get file names, paths, permissions. Find sensitive files which you may want to exfiltrate.
- *Network mapping*: what IP addresses are local? What is the [subnet](/nested-repos/PNPT-study-guide/practical-ethical-hacking/networking/subnetting.md)? What does the [routing table](/networking/routing/routing-table.md) have in it?
- *OS*: what is the CPU architecture? How much memory/RAM is there?
- etc.

#### Weaponization
Combining an exploit and malware into a deliverable payload. Once an attacker has finished gathering intelligence via the recon phase, they can use that to develop/ weaponize a tool which will take advantage of any discovered vulnerabilities of the target.

This part of the cyber kill chain

#### Delivery
How the weapon/payload gets delivered
*Examples*:
1. [watering-hole]()
2. [phishing](/cybersecurity/TTPs/phishing.md)
3. [candy-drop]()

#### Exploitation
When the attacker uses a vulnerability in a device/ system to gain access to the target system.

*Ex of exploits:*
1. a victim triggers the exploit by opening an email attachment/ clicking on a malicious link (phishing)
2. [zero-day]()
3. vulnerabilities in software/ hardware or even human
4. server-based vulnerabilities

#### Installation
Once an attacker is in, they need to install something to establish persistence (a way to gain access again)

##### Persistence:
Persistence is the first step once you're on a breached system. You need to be able to:
1. establish a way back in (backdoor)
2. avoid detection
##### a backdoor...
is a way for an attacker to establish a way back into the system while bypassing security measures. Can also be called an "access-point"

##### a persistent-backdoor...
allows an attacker to re-access a system they compromised in the past.

2. Persistence can be achieved through:
	1. installing a #web-shell on a web server
		1. a malicious script written in web-languages like #PHP and #JavaScript which allows the attacker to maintain access.
		2. usually web shells have simplistic file formatting w/ file extensions that are difficult to detect (.php, .asp, .jsp, etc.)
			1. might be classified as "benign"
	2. installing a backdoor on a victim's machine
		1. #Meterpreter can be used to install a backdoor
			1. a [metasploit](/cybersecurity/tools/metasploit.md) payload which gives the user an interactive shell which allows interaction with the victim's machine which can remotely execute malicious code
	3. creating or modifying a Windows service
		1. attacker creates or modifies a Windows service to execute malicious scripts/ payloads
			1. can use #sc/exe and #Reg to modify service configurations
			2. attacker can also #masquerade a payload by using service names which are known to be r/t the #OS or legitimate software.
	4. Adding the entry to the #run-keys of the malicious payload to the #Registry or #startup-folder.
		1. the payload will execute each time the user logs into the computer
	5. #timestomping
		1. a technique used by attackers to avoid forensic detection.
			1. Also helps make the malware appear legitimate
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
		- allows attacker to blend malicious traffic w/ legitimate traffic
		- helps them evade #firewalls
	- #DNS 
		- Attacker purchase/ registers a DNS server
		- infected machine makes DNS requests to the malicious DNS server
		- also called #DNS-tunneling

#### Exfiltration/ #exfiltration
1. ex: collecting user credentials, privilege escalation, internal recon, lateral movement thru network, collecting sensitive data, deleting backup/ #shadow-copies 
	1. a Shadow Copy is a Microsoft technology which creates backup copies, snapshots, etc of computer files and volumes
2. overwrite of #corrupt data

> [!Resources]
> - [TryHackMe: Cyber Kill Chain](https://tryhackme.com/room/cyberkillchainzmt)
> - [Lockheed Martin: Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
> - [Technical Aspects of Cyber Kill Chain](https://arxiv.org/pdf/1606.03184.pdf) Yadav, Mallari (2016)

