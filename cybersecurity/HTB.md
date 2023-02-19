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
		1. [[SQL]]
		2. [[SQL-injection]]
		3. [[PII]]
		4. [[OWASP]]
		5. [[TTPS]]
		6. [[gobuster]]
		7. 