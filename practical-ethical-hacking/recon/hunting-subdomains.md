
# Hunting Subdomains
There are both *active* and *passive* ways to find and identify subdomains of a target.
## Why Subdomains?
You may come across a bunch of different [subdomains](/networking/DNS/DNS.md) of a target domain during your investigation.

Gathering information on these subdomains is important because doing so will give you a better idea of the target landscape.
### Juicy Targets:
#### Production Environments:
- `dev.blank.blank`
- `qa.blank.blank`
- `stage`/`stg.blank.blank`
#### Abandoned Subdomains:
If someone has abandoned a subdomain, it is vulnerable to [subdomain takeover](cybersecurity/TTPs/delivery/subdomain-takeover.md).
##### What to look for:
Using the [dig](/CLI-tools/linux/dig.md) command, you can spot a vulnerable subdomain when the server responds with `NXDOMAIN`, `SERVFAIL`, `REFUSED`, or `no servers could be reached`.

Once you've found a subdomain which is possibly abandoned, you can `dig` that as well.
## [Sublist3r](https://www.kali.org/tools/sublist3r/)
Sublist3r is a tool written in python which can be used to enumerate subdomains. It does so using search engines like Yahoo, Google, etc. so it is considered OSINT (b/c it's not actively trying to find subdomains using something like a wordlist on a root domain).

Sublist3r is capable of finding 3rd and 4th level domains.

*However* Sublist3r can be used to do brute force (active/ not OSINT) enumeration using the Subbrute integrated tool.
### [Usage](/cybersecurity/tools/recon/sublist3r.md)

## OWASP [Amass](/cybersecurity/tools/amass.md)

## Certificate Fingerprinting:
Certificate fingerprint/ thumbprint is the hash of an SSL certificate derived from the certificate's data and signature. The thumbprint is used as a unique identifier for the certificate.
### [Crt.sh](https://crt.sh)
*This site returns a `502` at time of writing*

This site can be used to find subdomains deeper even than the second and third levels of a domain name. It can be used to find all of the sub and sub-sub-domains of a domain name.
## Other Resources:
### [DNS Dumpster](https://dnsdumpster.com/)
A free online tool which you can use to discover hosts r/t a domain. Also includes hosting IP block, DNS servers, MX Records, TXT Records, etc.. 

You can also get a map of the domain and subdomains like this:
![](/nested-repos/PNPT-study-guide/PNPT-pics/hunting-subdomains-1.png)
![](/PNPT-pics/hunting-subdomains-1.png)

> [!Resources]
> - [Sublist3r](https://www.kali.org/tools/sublist3r/)
> - [IPlocation.io](https://iplocation.io/ssl-certificate-fingerprint)
> - [OWASP: Test for Subdomain Takeover](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)
> - [AppSecco: Pentester's Guide to Subdomain Enumeration](https://blog.appsecco.com/a-penetration-testers-guide-to-sub-domain-enumeration-7d842d5570f6)

> [!My previous notes (linked in the text)]
> - [DNS](https://github.com/TrshPuppy/obsidian-notes/blob/main/networking/DNS/DNS.md)
> - [Sublist3r (usage)](https://github.com/TrshPuppy/obsidian-notes/blob/main/cybersecurity/tools/recon/sublist3r.md)
> - [dig command](https://github.com/TrshPuppy/obsidian-notes/blob/main/CLI-tools/linux/dig.md)
> - [Subdomain Takeover](https://github.com/TrshPuppy/obsidian-notes/blob/main/cybersecurity/TTPs/subdomain-takeover.md)
> - [Amass](https://github.com/TrshPuppy/obsidian-notes/blob/main/cybersecurity/tools/recon/amass.md)


