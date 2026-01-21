# Cybersecurity
This is a large directory containing all my notes r/t cybersecurity (not including my [PNPT](../PNPT/README.md) or [OSCP](../OSCP/README.md) notes). I've tried to organize them based loosely on the [Cyber Kill Chain](/cybersecurity/TTPs/cyber-kill-chain.md). The bulk of the interesting stuff can be found in [TTPs](/cybersecurity/TTPs).

Here is a short breakdown of each section:
### [Adversaries](/cybersecurity/adversaries)
Includes notes on specific adversaries such as APT groups.
### [Attacks](/cybersecurity/attacks)
Contains notes about specific, noteworthy incidents like [WannaCry](/cybersecurity/attacks/wannacry.md).
### [Bug Bounties](/cybersecurity/bug-bounties)
May change in the future, right now just includes my notes from HackerOne's Hacker101 course.
#### Sub Directories
- `/hackerone`
### [Defense](/cybersecurity/defense)
Contains notes on different defensive/ blue team techniques and/or tools. For example, [firewalls](/cybersecurity/defense/firewalls.md) and [DMARC](/cybersecurity/defense/DMARC.md).
#### Sub Directories
- `/appsec`
- `/incident-response`
- `/threat-intelligence`
### [Hardware Hacking](/cybersecurity/hardware-hacking)
Notes relating specifically to hardware. Right now all it contains is my notes on how radio frequencies work, lol. More to come.
### [Malware](/cybersecurity/malware)
Holds my notes related to specific, common/ noteworthy malware such as [Emotet](/cybersecurity/malware/emotet.md) and [conti](malware/conti.md).
### [Opsec](/cybersecurity/opsec)
Contains miscellaneous notes r/t opsec practices.
### [Pen Testing](/cybersecurity/pen-testing)
Contains notes related to penetration testing practices like [report writing](/cybersecurity/pen-testing/report-writing.md), etc.. Also putting notes on pen-testing specific services like [ElasticSearch](pen-testing/services/elasticsearch.md) here for now (think [HackTricks](https://book.hacktricks.wiki/en/index.html) style notes).
#### Sub Directories
- `/services`
### [Resources](/cybersecurity/resources)
Contains links to resources like [Akamai](resources/Akamai.md) and [OWASP](resources/OWASP.md) as well as conceptual notes on things like [CVEs](resources/CVEs.md) and [CVSS](resources/CVSS.md).
#### Sub Directories
- `/corelan`
- `/portswigger-academy`
- `/pwn-college` 
- `/WSTG` (OWASP Web Security Testing Guide)
### [TTPs](/cybersecurity/TTPs)
This directory is LARGE and is organized based on the [Cyber Kill Chain](TTPs/cyber-kill-chain.md) (don't judge me, I needed a good way to organize everything). Each sub directory has a `/tools` sub-directory within it which is how I've been organizing specific command line tools for hacking (such as [hashcat](TTPs/cracking/tools/hashcat.md) for example). Some things still don't perfectly fit into this hierarchy so I apologize (but damn, I've put too much time into organizing this fuggin thing so BITE ME).
#### Sub Directories
- `/actions-on-objective`
- `/c2`
- `/cloud`
- `/cracking`
- `/delivery`
- `/exploitation`
- `/persistence`
- `/recon`
### [Vulnerabilities](/cybersecurity/vulnerabilities)
This holds my notes on various specific vulnerabilities. For example [EternalBlue](vulnerabilities/EternalBlue.md) and [openfuck](/cybersecurity/vulnerabilities/openfuck.md).
### [Wifi](wifi/README.md)
I didn't know where to put wifi hacking stuff so its here.