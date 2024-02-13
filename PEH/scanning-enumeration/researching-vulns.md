
# Researching Potential Vulnerabilities
Based on what we've found in our scanning and enumeration of Kioptrix, we need to research the vulnerabilities we may have identified.
## The Findings
Ranked in order of what we feel would be the easiest to exploit and/ or most vulnerable:
```bash
Target: 10.0.3.5
Ports w/ findings:
	80: HTTP
		:80/
			Default page for Apache Web Server:
				Apache v1.3.20 (Unix) (Red-Hat/Linux)
				mod_ssl v2.8.4
		:80/manual/*
			manual pages for Apache HTTP Server Version 1.3b5
		:80/manual/mod/mod_ssl/*
			manual pages for mod_ssl v2.8.31
	443: HTTPS
			Apache/1.3.20 (Unix)  (Red-Hat/Linux) 
				mod_ssl v2.8.4 
				OpenSSL v0.9.6b
				SSLv2 supported
	139: Samba/ NetBIOS
		workgroup: MYGROUP
		Anonymous login allowed (no password)
		Shares:
			IPC$
			ADMIN$
		SMB version 2.2.1a
		ntlmv2
	445: 
	22: SSH
		OpenSSH 2.9p2 
```
## Finding Pre-existing Exploits & CVEs
Starting w/ `mod_ssl`, the version we've found using nmap is `2.8.4`. Using that, we can search for vulnerabilities/ exploits r/t this exact version. There are a few resources we can use to do this.
### [Exploit DB](cybersecurity/tools/exploitation/exploit-db.md):
Exploit DB is a database of malware. The malware can be perused [online](https://www.exploit-db.com/exploits/764) or downloaded into a VM and looked through/ used that way. *When downloading, malware should be downloaded into an isolated environment* b/c it will carry out its designed actions when executed.

Exploit DB can also be searched via the command line using the [searchsploit](cybersecurity/tools/exploitation/searchsploit.md) command.
```bash
searchsploit mod_ssl 2.8.4
Exploit Title                                               |  Path
--------------------------------------------------------------------------------------
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow                                                                              | unix/remote/21671.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (1)                                                                        | unix/remote/764.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)                                                                        | unix/remote/47080.c
--------------------------------------------------------------------------------------
Shellcodes: No Results
```
Using either the online database, or `searchsploit`, we find [`OpenFuck`](/cybersecurity/vulnerabilities/openfuck.md) which is a remote [buffer overflow](cybersecurity/TTPs/exploitation/binary-exploitation/buffer-overflow.md). From the online database, you can review the code of the exploit itself:
![](nested-repos/PNPT-study-guide/PNPT-pics/researching-vulns-1.png)
![](/PNPT-study-guide/PNPT-pics/researching-vulns-1.png)
> [Exploit DB: OpenFuckV2.c](https://www.exploit-db.com/exploits/764)

**You can also just Google for `mod_ssl 2.8.4 exploit` / `vulnerability` and find similar results**
### Notetaking:
Keep notes on the vulnerabilities you find so you they're easier to reference when you write your [report](/cybersecurity/pen-testing/report-writing.md).
#### Example:
`vulnerabilities.txt`
```bash
80/443: Potentially vulnerable to OpenFuck (https://www.exploit-db.com/exploits/764)
```
## Determining Severity:
Now let's search for vulnerabilities and exploits r/t `Apache v1.3.20` (the [HTTP](www/HTTP.md) server running on `port 80`).
### [CVE Details](https://cvedetails.com)
CVE Details is another source we can use to research our vulnerabilities. If we search `apache 1.3.20` we can find multiple [CVEs](cybersecurity/resources/CVEs.md) r/t the server we found.

Each CVE is *rated based on severity* (1-10) using the [CVSS](cybersecurity/resources/CVSS.md) (Common Vulnerability Scoring System). We want to find one for our server version which has a high severity.
### Vulnerability Scoring (CVSS):
The CVSS for a CVE is determined using three metrics:
#### 1. Base
A base score given based on some sub-metrics. These submetrics determine  either the *exploitability or impact* of the vulnerability. The Base score will changed based on the Temporal and Environment metrics.
#### 2. Temporal
Changes made to the base score based on how present, available, and accurate the code for an exploit is for the CVE is.
#### 3. Environment
Changes the Base Score by taking into account the mitigation measures taken or in place by individual enterprises. This metric allows organizations to change the overall CVSS score of a CVE based on the protections they have against it.

For the `OpenFuck` exploit we found in `mod_ssl 2.8.4`, [NIST has given it](https://nvd.nist.gov/vuln/detail/CVE-2002-0082) a Base Score of *7.5 (High)* (using CVSS version 2). So we can infer that the severity of this vulnerability is high. Likely, the exploit code is easily available, widespread, and simple to execute.

The CVSS may be high for other reasons as well, but, given this scores is only the Base Score w/o the Temporal or Environmental modifiers, we should remember that the score may be different for our target.
## Working through other vulnerabilities
Given our list of potential vulnerabilities, here is a summary of what we can find on them using the workflow above:
`vulnerabilities.txt`
```bash
80/443: mod_ssl v2.8.4
	Potentially vulnerable to OpenFuck (https://www.exploit-db.com/exploits/764)
	- OpenFuck/ CVE-2002-0082: CVSS 7.5 (NIST)

139: Samba v2.2.1a
	Potentially vulnerable to trans2open 
	(https://www.rapid7.com/db/modules/exploit/linux/samba/trans2open/)
	- trans2open/ CVE-2003-0201: CVSS 10.0 (NIST)

22: OpenSSH v2.9p2 
	Potentially vulnerable to memory corruption via CVE-2021-28041
	(https://www.cvedetails.com/cve/CVE-2021-28041)
	- CVE-2021-28041: CVSS 4.6 - 7.1 (NIST)
```
With these metrics listed, the `trans2open` exploit looks like it may be the most successful for our effort.
### [trans2open](/cybersecurity/vulnerabilities/trans2.md)/ CVE-2003-0201
Researching more on this specific vulnerability can tell us more about how successful it could be. According to NIST, this CVE was last modified in 2018, using CVSS v2 which gave it a score of 10.0. The Base Score breakdown is:
![](nested-repos/PNPT-study-guide/PNPT-pics/researching-vulns-3.png)
![](/PNPT-study-guide/PNPT-pics/researching-vulns-3.png)
> [NVD](https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?name=CVE-2003-0201&vector=(AV:N/AC:L/Au:N/C:C/I:C/A:C)&version=2.0&source=NIST)

Looking at [CVE Details](https://www.cvedetails.com/epss/CVE-2003-0201/epss-score-history.html) we can see that the [EPSS](cybersecurity/resources/EPSS.md) (Exploit Prediction Scoring System) for this CVE is *96.89%* which reflects the likelihood of trans2open being used in the next 30 days. This score was re-calculated *in March of 2023*, lending to the temporal severity.
![](nested-repos/PNPT-study-guide/PNPT-pics/researching-vulns-2.png)
![](/PNPT-study-guide/PNPT-pics/researching-vulns-3.png)
> [CVE Details](https://www.cvedetails.com/epss/CVE-2003-0201/epss-score-history.html)

Thinking back on how the CVSS is calculated, we know that increased activity and availability of the exploit code *increases the overall severity* of the CVE. CVE Details also tells us that there are a few [Metasploit](cybersecurity/tools/exploitation/metasploit.md) modules which make this vulnerability even easier to exploit.

> [!Resources]
> - [Exploit DB: OpenFuckV2.c](https://www.exploit-db.com/exploits/764)
> - [CVE Details](https://cvedetails.com)
> - [NIST: CVE-2002-0082](https://nvd.nist.gov/vuln/detail/CVE-2002-0082)
> - [NIST: CVE-2003-0201](https://nvd.nist.gov/vuln/detail/CVE-2003-0201)
> - [CVE Details: CVE-2021-28041](https://www.cvedetails.com/cve/CVE-2021-28041)
> - [CVE Details: CVE-2003-0201](https://www.cvedetails.com/cve/CVE-2003-0201/)
> - [NVD: CVSS calculator for CVE-2003-0201](https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?name=CVE-2003-0201&vector=(AV:N/AC:L/Au:N/C:C/I:C/A:C)&version=2.0&source=NIST)

> [!My previous notes (linked in text)]
> - [searchsploit](https://github.com/TrshPuppy/obsidian-notes/tree/main/cybersecurity/tools/reverse-engineering/searchsploit.md)
> - [buffer overflow](https://github.com/TrshPuppy/obsidian-notes/tree/main/cybersecurity/TTPs/exploitation/buffer-overflow.md)
> - [report writing](https://github.com/TrshPuppy/obsidian-notes/tree/main/cybersecurity/pen-testing/report-writing.md)
> - [HTTP](https://github.com/TrshPuppy/obsidian-notes/tree/main/networking/protocols/HTTP.md)
> - [CVEs](https://github.com/TrshPuppy/obsidian-notes/tree/main/cybersecurity/literature/CVEs.md)
> - [CVSS](https://github.com/TrshPuppy/obsidian-notes/tree/main/cybersecurity/literature/CVSS.md) 
> - [trans2open](https://github.com/TrshPuppy/obsidian-notes/tree/main/cybersecurity/vulnerabilities/trans2.md)
> - [Metasploit](https://github.com/TrshPuppy/obsidian-notes/tree/main/cybersecurity/tools/metasploit.md)
> - [EPSS](https://github.com/TrshPuppy/obsidian-notes/tree/main/cybersecurity/literature/EPSS.md) 



