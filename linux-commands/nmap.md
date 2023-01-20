
# usage
```
nmap [Scan Type(s)] [Options] {target sppecification}
```

## useful options:
#nmap-sT
	- Scanning for [[TCP-IP]] 
	- syntax: for TCP: ``nmap -sT {target}``
- #nmap-sS
	- scan for SYN connects
- #nmap-sV
	- probe open ports to determine service/version info
	- syntax: ``nmap -sV {target}``
- #nmap-O
	- enable OS detection
		- **needs root/sudo**