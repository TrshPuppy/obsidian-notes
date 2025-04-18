
# Web App Testing Tools
## Fingerprinting Web Servers
[nmap](../../CLI-tools/linux/remote/nmap.md) is a common tool used for fingerprinting target webservers. First, we can start with service discovery with `-sV` on any open web/[HTTP](../../www/HTTP.md) ports we found on the target:
```bash
kali@kali:~$ sudo nmap -p80  -sV 192.168.50.20
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-29 05:13 EDT
Nmap scan report for 192.168.50.20
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
...
```
Next, we can do *service specific* script scanning using Nmap's NSE:
```bash
kali@kali:~$ sudo nmap -p80 --script=http-enum 192.168.50.20
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-29 06:30 EDT
Nmap scan report for 192.168.50.20
Host is up (0.10s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /login.php: Possible admin folder
|   /db/: BlogWorx Database
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
|   /db/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
|   /js/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
|_  /uploads/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'

Nmap done: 1 IP address (1 host up) scanned in 16.82 seconds
```
The `http-enum` script found some potentially juicy web directories on our target. 
## Tech Stack
We can use [Wappalyzer](../../PNPT/PEH/recon/website-tech-recon.md#Wappalyzer) to discover more about the target server's tech stack:
![Wappalyzer](../../PNPT/PEH/recon/website-tech-recon.md#Wappalyzer)
[My notes on Wappalyzer](../../PNPT/PEH/recon/website-tech-recon.md#Wappalyzer)
## Directory Busting
[Gobuster](../../cybersecurity/TTPs/recon/tools/dir-and-subdomain/gobuster.md) is a good tool for [directory busting](../../cybersecurity/TTPs/recon/directory-enumeration.md) to find more directories. There is also [dirb](../../cybersecurity/TTPs/recon/tools/dir-and-subdomain/dirb.md), [feroxbuster](../../cybersecurity/TTPs/recon/tools/dir-and-subdomain/feroxbuster.md), and [ffuf](../../cybersecurity/TTPs/recon/tools/dir-and-subdomain/ffuf.md) (among others).
## Burp Suite
[Burp Suite](../../cybersecurity/TTPs/delivery/tools/burp-suite.md) is a GUI-based tool for testing a web app by intercepting [HTTP](../../www/HTTP.md) requests. The free version can be used for manual testing, but the paid version also offers web app vuln scanning and other tools.
![burp-suite](../../cybersecurity/TTPs/delivery/tools/burp-suite.md)
[My notes on Burpsuite](../../cybersecurity/TTPs/delivery/tools/burp-suite.md)



> [!Resources]
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.