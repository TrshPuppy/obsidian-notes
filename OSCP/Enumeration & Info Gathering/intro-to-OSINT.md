
# Passive Reconnaissance
Also known as [OSINT](../../cybersecurity/TTPs/recon/OSINT.md) (open source intelligence) gathering. The process of finding and collecting *publicly available information* on a target *without directly interacting* with the target. The ultimate goal of passive reconnaissance is to *discover information which clarifies or expands the target's attack surface.* We're interested in any information which will help us exploit the target, whether by [phishing](../../hidden/Sec+/24%%201%20Attacks,%20Threats%20&%20Vulnerabilities/1.1%20Social%20Engineering/phishing.md), malware delivery, password guessing, etc..
## Schools of Thought
... on what 'passive' actually means.
### Strict interpretation
We *NEVER* communicate directly w/ the target and instead rely on *third-party* information. In other words, we *never interact with the target's systems or servers*. 

Strict passive recon maintains secrecy so the target can't guess at or know our actions or intentions. However, it can also be *cumbersome* and slow-going.
### Loose interpretation
Gathering OSINT by interacting with the target *as a normal user would*. For example, if the target's website has a 'register user' function, then we use it as a normal user would to try and gain information about the target.

We would *not do any testing* of the target for vulnerabilities, etc.. The idea is to gather public information which is readily available to any internet user. This type of reconnaissance *leaves a trace* or our actions which the target may discover and use to try to interpret our intentions (or as a means to re-create/ track down steps we take later on).
## Table of Contents (Passive Strats)
- [WHOIS-enum](WHOIS-enum.md)
- [google-dorks](google-dorks.md)
- [open-source-code](open-source-code.md)
- [netcraft](netcraft.md)
- [security-headers-SSL](security-headers-SSL.md)
# Active Reconnaissance
Information we gather on the target through active strategies means we've gathered it by interacting w/ the target directly. Usually, this info is gathered using automated tools such as [netcat](../../cybersecurity/TTPs/exploitation/tools/netcat.md) or [nmap](../../CLI-tools/linux/remote/nmap.md), etc.. Most active reconnaissance infolves *enumeration* of external services and ports. This includes enumerating ports during port scanning, and enumerating services which return information for us like [SMB](../../networking/protocols/SMB.md), [DNS](../../networking/DNS/DNS.md), [SMTP](../../networking/protocols/SMTP.md), [SNMP](../../networking/protocols/SNMP.md), etc..
## Windows LOLBins
In most internal pen-tests, the client gives us *assumed breach* access to their internal network, usually via a Windows machine. There are a lot of tools which are pre-installed and trusted on a Windows system which we can use to do active recon. These are called *Living off the Land binaries* (LOLBins, sometimes also called LOLBAS for LOL binaries, scripts, and libraries).
## Table of Contents (Active Strats)
- 


> [!Resources]
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.
