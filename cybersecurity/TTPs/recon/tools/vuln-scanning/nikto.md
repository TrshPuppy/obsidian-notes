
# Nikto Vulnerability Scanner
Nikto is a command line tool on kali linux which scans *web servers* for vulnerabilities.
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
#### `-port`
Nikto will *only test `port 80`* unless you use this flag to identify more [TCP](/networking/protocols/TCP.md) ports. You can use a range or a comma-delimited list.
#### `-list-plugins` Plugins:
Will list all the plugins available to use in a scan w/o executing a scan.
#### `-plugins`:
Choose specific plugins to use for a scan (comma-separated list).
#### `-Tuning`: Tuning options
> **IMPORTANT:** Nikto is *not* a passive scan. It will perform active pentesting techniques to gather information, including [SQL Injection](/cybersecurity/TTPs/exploitation/injection/SQL-injection.md), [directory busting](/cybersecurity/TTPs/recon/directory-enumeration.md), [XSS](/cybersecurity/TTPs/exploitation/injection/XSS.md), etc..
> For example, the Nikto plugin `nikto_dictionary_attack.plugin` performs a dictionary attack on the target to determine if it's vulnerable to this technique.

The `-Tuning` flag allows you to choose specifically which tests you want run on a target:
```bash
man nikto
...
-Tuning
        Tuning options will control the test that Nikto will use against a
        target. By default, if any options are specified, only those tests will
        be performed. If the "x" option is used, it will reverse the
        logic and exclude only those tests. Use the reference number or letter
	    to specify the type, multiple may be used:
	    
           0 - File Upload
           1 - Interesting File / Seen in logs
           2 - Misconfiguration / Default File
           3 - Information Disclosure
           4 - Injection (XSS/Script/HTML)
           5 - Remote File Retrieval - Inside Web Root
           6 - Denial of Service
           7 - Remote File Retrieval - Server Wide
           8 - Command Execution / Remote Shell
           9 - SQL Injection
           a - Authentication Bypass
           b - Software Identification
           c - Remote Source Inclusion
           x - Reverse Tuning Options (i.e., include all except specified)
           
        The given string will be parsed from left to right, any x characters
        will apply to all characters to the right of the character.
```
#### `-evasion`: LibWhisker Evasion Techniques
This flag allows you to tell Nikto what LibWhisker IDS evasion technique to use:
```bash
man nikto
...
-evasion
        Specify the LibWhisker IDS evasion technique to use (see the LibWhisker
        docs for detailed information on these). Use the reference number to
        specify the type, multiple may be used:
        
           1 - Random URI encoding (non-UTF8)
           2 - Directory self-reference (/./)
           3 - Premature URL ending
           4 - Prepend long random string
           5 - Fake parameter
           6 - TAB as request spacer
           7 - Change the case of the URL
           8 - Use Windows directory separator (\)
```

> [!Resources]
> - `man nikto`
> - My [other notes](https://github.com/TrshPuppy/obsidian-notes) (linked throughout the text)
