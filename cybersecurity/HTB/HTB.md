---
aliases: [HTB, hack-the-box]
---
## Starting Point

1. Tier Zero:
	1. Meow
		1. [[virtual-machine]]s
		2. [[telnet]] 
		3. #port-23 
		4. [[telnet-command]]
		5. [[VPN]]
		6. [[ICMP]]
		7. [[nmap]] 
		8. [[TCP]]
	2. Fawn
		1. [[FTP]]
		2. [[ftp-command]]
		3. #anonymous-ftp 
		4. #port-21 
		5. #SFTP
	3. Dancing
		1. [[SMB]]
		2. #port-445
		3. #nmap-sV 
		4. [[smbclient]]
		5. #smbclient-L 
		6. #smbclient//fileserver/Backup 
	3. Redeemer
		1. [[TCP]]
		2. [[redis]]
		3. [[redis-cli]]
	4. Explosion
		1. [[RDP]]
		2. [[xfreerdp]]
		3. [[BlueKeep]]
		4. [[DejaBlue]]
		5. #port-3389 
	5. Preignition
		1. #nginx
			- HTTP reverse proxy server
		2. [[HTTP]]
		3. #port-80 
		4. [[gobuster]] 
			1. #URI
			2. seclists
			3. wordlists
	6. Mongod
		1. [[MongoDB]]
		2. #noSQL
			1. relational vs non-tabular
				1. #RDBMS 
				2. #noSQL 
				3. #column-store / #C-store
		3. [[mongo]]
			1. #mongosh
			2. **mongo shell javascript code?
		4. [[rsync]]
			1. #port-873
			2. 


2. Tier One:
	1. Appointment
		1. [SQL](/coding/languages/SQL.md)
		2. [[SQL-injection]]
		3. [[PII]]
		4. [[OWASP]]
		5. [[TTPS]]
		6. [[gobuster]]
	2. Sequel
		1. [mysql](mysql.md)
			1. USE
			2. DESCRIBE
			3. SHOW TABLES
		2. mariaDB
	3. Crocodile 
		1. nmap
			1. -sC (scripts)
		2. ftp
			1. get
			2. anonymous
			3. codes
		3. http/gobuster
	4. Responder
		1. [LFI Vulnerability](/cybersecurity/vulnerabilities/LFI.md)
		2. [RFI Vulnerability](/cybersecurity/vulnerabilities/RFI.md)
		3. [NTLM](/networking/protocols/NTLM.md)
			1. #Kerberos 
		4. [Responder](/cybersecurity/tools/responder.md)
		5. [LLMNR](/networking/protocols/LLMNR.md)
		6. [john the ripper](/cybersecurity/tools/john.md)
		7. evil-winrm
	5. Three
		1. 

CTF stuff w/ codecore https://ctftime.org/
- past write ups: archive
- VM

#virtual-hosting:  one server can server several virtual hosts
![[Pasted image 20230221191650.png]]
#DNS-enumeration
HTTP request #host-header 
#etc-host
#resolving
WHAT IS THE HOST FILE ("always know where the host file is")

curl -L (layers?)
- curl cant execute code like your browser will
- "index of" --> directory traversal