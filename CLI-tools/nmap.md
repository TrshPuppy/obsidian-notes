
# usage
```
nmap [Scan Type(s)] [Options] {target sppecification}
```

## useful options:
TCP connect scan: #nmap-sT
- Scanning for [TCP](/networking/protocols/TCP.md) 
- syntax: for TCP: ``nmap -sT {target}``
SYN connect scan #nmap-sS
- scan for SYN connects
Service/Version #nmap-sV
- probe open ports to determine service/version info
- syntax: ``nmap -sV {target}``
OS detection #nmap-O
- enable OS detection
	- **needs root/sudo**
Limit number of ports scanned: `-p <number or range>`

## Types of scans:
1. TCP connect scans (`-sT`)
	- #3-way-handshake
	- If nmap receives an #ACK-flag the port is _open_
	- #RST-flag (reset) means the port is _closed_
	- a port is likely *hidden behind a firewall* if there is no response
		- b/c the firewall will drop the packet 
		- ==unless== the firewall is configured to response with a fabricated RST flag
2. SYN ("half open", "stealth") ( #nmap-sS)
	- ==This is the default== when running nmap w/ `sudo`
	- When the target sends the #SYN/ACK-flag, client then sends #RST-flag to prevent the target from repeatedly sending requests.
		- Can bypass older #IDS which only scan for a full 3 way handshake
		- Prevents logging of the connection b/c most apps listening to the port only log fully-established connections.
		- ==faster than TCP connect scan==
	- Disadvantages:
		- requires root privileges
		- may cause an unstable target service to crash
3. [UDP](/networking/protocols/UDP.md) scans: ( #nmap-sU)
	- UDP is ==stateless== 
		- it doesn't require a handshake
	- more difficult to scan for:
		- When there is no response when a packet is sent to an ==open== UDP port:
			- nmap marks response as "`open|filtered`"
		- ==closed port== : nmap receives an [ICMP](/networking/protocols/ICMP.md) "ping" packet which nmap marks as closed
	- Disadvantages:
		- scans take longer
			- ==tip== if scanning with `-sU` use `top-ports` so it only scans the top 1000 ports
3. Less common scans:
	- These scans are stealthier because they send ==malformed packets==
		- Most firewalls automatically block incoming requests w/ the SYN flag but don't block packets ==without== the SYN flag
	1. NULL scan ( #nmap-sN)
		- a TCP request sent without any flags set (packet is empty)
		- closed port: responds w/ "RST"
	2. FIN ( #nmap-sF)
		- sends request w/ the #FIN-flag set
		- closed port: responds w/ "RST"
	3. Xmas ( #nmap-sX)
		- sends  a malformed TCP packet
		- closed ports respond w/ "RST"
		- open ports: no response because the packet is dropped by the target
		- ==bonus== called "Xmas" b/c of how it looks in #wireshark