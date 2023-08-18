
# Nikto Vulnerability Scanner
Nikto is a command line tool on kali linux which scans web servers for vulnerabilities.
## Usage
```bash
NAME
       nikto - Scan web server for known vulnerabilities
SYNOPSIS
       nikto [options...]
DESCRIPTION
       Examine a web server to find potential problems and security
       vulnerabilities, including:

       •   Server and software misconfigurations
       •   Default files and programs
       •   Insecure files and programs
       •   Outdated servers and programs

       Nikto is built on LibWhisker (by RFP) and can run on any platform which
       has a Perl environment. It supports SSL, proxies, host authentication,
       IDS evasion and more. It can be updated automatically from the command-
       line, and supports the optional submission of updated version data back
       to the maintainers.
...
```
### Useful flags:
#### `-h` Host:
```bash
nikto -h 10.0.3.5
```
#### `-list-plugins` Plugins:
Will list all the plugins available to use in a scan w/o executing a scan.
#### `-plugins`:
Choose specific plugins to use for a scan (comma-separated list).
#### `-Tuning`: Tuning options
**IMPORTANT:** Nikto is *not* a passive scan. It will perform active pentesting techniques to gather information, including [SQL Injection](cybersecurity/TTPs/injection/SQL-injection.md), [directory busting](cybersecurity/TTPs/enumeration/directory-enumeration.md), [XSS](/cybersecurity/TTPs/)
