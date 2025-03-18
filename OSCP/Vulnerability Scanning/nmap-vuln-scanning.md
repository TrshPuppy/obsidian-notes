
# Vulnerability Scanning w/ Nmap
[nmap](../../CLI-tools/linux/remote/nmap.md) vuln scanning is done through it's [Nmap Scripting Engine](../../CLI-tools/linux/remote/nmap.md#Nmap%20Scripting%20Engine). Unfortunately, a lot of the scripts (in the "vulns" category) are outdated. Fortunately, the "vulners" script from the [Vulners Vulnerability Database](https://vulners.com/) was integrated so nmap can make use of current and update vulnerabilities.

Vuln scanning with nmap is considered 'light weight' and is mostly useful for verifying findings by other vuln scanners, or supplementing when we don't have access to a vuln scanner.
## Vulners script
The "vulners" script comes w/ categories "safe", "vuln", and "external". The vulners script can be ran just by using the `"vuln"` category with an nmap script scan:
```bash
sudo nmap -sV -p 443 --script "vuln" 192.168.50.124
Starting Nmap 7.92 ( https://nmap.org )
...
PORT    STATE SERVICE VERSION
443/tcp open  http    Apache httpd 2.4.49 ((Unix))
...
| vulners: 
|   cpe:/a:apache:http_server:2.4.49:
...
        https://vulners.com/githubexploit/DF57E8F1-FE21-5EB9-8FC7-5F2EA267B09D	*EXPLOIT*
|     	CVE-2021-41773	4.3	https://vulners.com/cve/CVE-2021-41773
...
|_http-server-header: Apache/2.4.49 (Unix)
MAC Address: 00:0C:29:C7:81:EA (VMware)
...
```
In the above snippet, you can see the results from the Vulners database. The vulners script uses information from the *service and versions portion of the scan `-sV`* to find vulnerabilities which are related.
### Proof of Concept
The vulners script will also provide a *proof of concept* for found vulnerabilities (unless the service scan was unsuccessful). POCs are marked in the output with `*EXPLOIT*`.
## Adding CVE Checks to the NSE
![Updating the NSE](../../CLI-tools/linux/remote/nmap.md#Updating%20the%20NSE)
[Updating the NSE](../../CLI-tools/linux/remote/nmap.md#Updating%20the%20NSE)


> [!Resources]
> - [Vulners Vulnerability Database](https://vulners.com/)