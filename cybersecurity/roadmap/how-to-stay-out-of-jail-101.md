
x68 1/23/23
# How To Stay Out of Jail 101
Example of bad form:
- Iowa:
	- physical pentest of courthouse
		- ROE were unclear
			- company lawyers, personal lawyers should be involved
			- they were in jail for a few months
- Missouri:
	- f12 /inspect browser incident w/ journalist
	- governer felt f12 was "hacking"

#Bug-bouties:
- What are the rules?
	- ex: Arkansas has no differentiation b/w security hacking and hacking.
- HackerOne.com
	- manages bug bounties for companies
	- vendors authorize your reporting of bugs you find
- #Responsible-disclosure:
	- if u find a vulnerability:
		- cant just post a blogpost on it
		- #kevin-mitnick
		- #CVE - Common Vulnerability E...
			- CVEdetails.com
			- document of a vulnerability
				- shows year, #CVSSscore (how dangerous it is)
				- access complexity
				- whether you need authentication
				- whether you gain access or not w/ the vulnerability
				- #metapsloit modules
	- some companies will not patch a vulnerability even after uve told them
	- If a company doesn't have a way to do responsible disclosure, try to find the CSO and message them
- [[THM|THM]]

[[shodan.io]] 
search engine for finding 'stuff' on the internet
- will show u machines running open ports which are exposed to the internet
- #port-5432 
	- can search for all ports open in the US
		- some may be #honey-pots
		- (don't poke at them)
		- #I-can-spam-act
		- #port-scanning:
			- will leave behind evidence of you scanning ( [[nmap]])
	- #niagara-fox (software with serious vulnerabilities)
		- you can use shodan to scan for computers whcih are running niagra fox and see which versions they are running
	- #HVAC system exploit Target 2014/2013
- #port-3389 (remote desktop protocol [[RDP]] )
- #port-443:ISS / web mail
	- being conditioned to a warning
- #industrial-control-systems
	- #port-102
	- #siemens 
		- zero-day against Iranians
- [[OSINT]]
- #snmp
	- version 1: super insecure
- #botnet-barn
- #synology
- #mitre 
- #buffer-overflow 

IPv4 vs IPv6:
- #network-address-translation layer

#insecam
[[exploit-db]]

- actually has exploit code etc
	- if you run it against a machine it is a felony!
- read the exploit and understand what it does before trying to use it
- 