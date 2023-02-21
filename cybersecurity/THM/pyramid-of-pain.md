
# Pyramid of Pain
Cyber threat intelligence model designed by #David-Bianco
	- A pyramid of the types of Indicators of Compromise ( #IOC s) you will see and how much it will *hurt the threat actor* for you to deny them these indicators.

![[Pasted image 20230118194706.png]]
### Types of Indicators
1. #hash-values 
	1. Defensive standpoint: Can be used to as a unique reference to specific samples of malware or to files involved in an incident
	2. ==tools: ([[OPSWAT]], [[Virus-Total]], [[Cyber-Chef]])
	3. ==see: ([[hashing]]) 
2. #IP-addresses 
	- Defensive standpoint: can be blocked, dropped, or denied by a firewall
		- not always bulletproof
		- *easy* for a threat actor to recover from
	- ==ex: [[Fast-Flux]]==
3. #domain-names 
	- Harder for an attacker to recover from/ change because they have to re-register, modify [DNS](/networking/routing/DNS.md) records and purchase new domains
		- However, DNS providers have #APIs which make it easy to purchase/register domains
	- [punycode](/cybersecurity/attacks/punycode.md)
		- using Unicode to encode non-ASCII characters
	- [URL-shorteners](/cybersecurity/attacks/URL-shorteners.md)
4. #host-artifacts 
	- More annoying for a hacker if you're able to detect the observable traces they've left on a victimized system.
	- may include: #registry-values, suspicious process execution, attack patterns/ #IOC s, files left by malicious applications.
5. #network-artifacts 

- #zsh
	- zshrc file

host Artifacts
- #emotet
- https://en.wikipedia.org//wiki/Locard's_exchange_principle
- Dynamic Binary Instrumentation (DBI) frameworks
	- https://criticaldefence.com/malware-analysis-part-1/

Network artifacts
- #user-agent-string
	- wireshark
	- #tshark (command)

> [!links]
> https://www.sans.org/tools/the-pyramid-of-pain/
