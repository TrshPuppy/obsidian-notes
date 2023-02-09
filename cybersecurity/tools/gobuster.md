
# Gobuster
Gobuster is a tool used to brute-force URIs including directories and files as well as DNS subdomains.

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
- Modes:
	- `dir`: directory enumeration
	- `vhost`: enumerate virtual hosts
	- `dns`: enumerating subdomains
- Options:
	- `-o <output string>` File to save output to
	- `-v` verbose output
	- `-x <fie extension` to see pages w/ listed extensions:
		- ex: `-x php,html`

### Tips:
- To get a list of options specific to a mode use `gobuster <mode> -h`
- 