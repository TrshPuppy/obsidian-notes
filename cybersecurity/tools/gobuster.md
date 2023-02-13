
# Gobuster
Gobuster is a tool used to #brute-force #URIs including directories and files as well as #DNS subdomains.
- Enumerates hidden directories and files

## Usage:
```
gobuster <mode> [OPTIONS]
```
example:
```
gobuster dir -u <IP Address> -w <path to wordlist>
This example scans an IP address for directory busting using a wordlist
```

### Useful Options:
- Modes: ==help: `gobuster <mode> -h`==
	- `dir`: directory enumeration
		- includes hidden directories/files
		- can use `-u` to specify a target domain/ IP
		- use `-w` to specify the path to the #wordlist you want to use to enumerate directory/ file names 
	- `vhost`: enumerate virtual hosts
		- #virtual-hosting = when companies etc. host multiple domain names on a single server or cluster of servers.
			- one server is able to share data and resources with the other #hostnames 
	- `dns`: enumerating subdomains
		- use `-d` to specify a target domain you want to find a #subdomain in
		- `-w` for a wordlist
- Options: ==help: `gobuster -h` or `gobuster <mode> -h`==
	- `-o <output string>` File to save output to
	- `-v` verbose output
	- `-x <fie extension` to see pages w/ listed extensions:
		- ex: `-x php,html`
- Target Specification:
	-  

### Tips:
- To get a list of options specific to a mode use `gobuster <mode> -h`
- Gobuster is written in  #golang which makes it faster than similar tools
- ==Disadvantage:== Can't do recursive enumeration (if you want to enumerate on directories below the outer directory, you have to run it again with the next directory deep as the target)