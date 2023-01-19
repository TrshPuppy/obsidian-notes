https://www.sans.org/tools/the-pyramid-of-pain/

Cyber threat intelligence model designed by #David-Bianco
	- A pyramid of the types of Indicators of Compromise ( #IOC s) you will see and how much it will *hurt the threat actor* for you to deny them these indicators.

![[Pasted image 20230118194706.png]]
	-Types of Indicators:
		1. #hash-values
			- [[hashing]]
			- Defensive standpoint: Can be used to as a unique reference to specific samples of malware or to files involved in an incident
				- ([[OPSWAT]], [[Virus-Total]], [[Cyber-Chef]])
		2. #IP-addresses 
			- Defensive standpoint: can be blocked, dropped, or denied by a firewall
				- not always bulletproof
				- *easy* for a threat actor to recover from
				- [[Fast-Flux]]
				- 


- #ASN
- #zsh
	- zshrc file
- ``curL -L -I $URL``
	- follows redirect 
	- ``-I`` = only show headers
	- So if there is a redirect, you should see an HTTP/3xx. If you see that you'll get the expanded URL

host Artifacts
- #emotet
- https://en.wikipedia.org//wiki/Locard's_exchange_principle
- Dynamic Binary Instrumentation (DBI) frameworks
	- https://criticaldefence.com/malware-analysis-part-1/

Network artifacts
- #user-agent-string
	- wireshark
	- #tshark (command)