
# (PASSIVE) Netcraft
[Netcraft](https://www.netcraft.com/tools/) is an internet service provider which also has a free web search engine you can use for various information gathering. It is based out of England and offers functionality such as returning information on what kinds of software/ technology is running on a website or target, as well as [ASN](../../networking/ASN.md) and [DNS](../../networking/DNS/DNS.md) information.
## Tools
### [DNS Lookup](https://sitereport.netcraft.com/?url=http://www.megacorpone.com)
Returns information on a queried domain name like DNS records, registration info, technology, [IP addresses](../../networking/OSI/3-network/IP-addresses.md) ranges, [Name Servers](../../networking/DNS/DNS.md#Name%20Servers), etc.. You can give the search engine a wildcard to return subdomains. For each subdomain returned, Netcraft includes a [site report](https://searchdns.netcraft.com/?restriction=site+contains&host=*.megacorpone.com&position=limited).
### Technologies
Even from the site report returned by the DNS tool, we can scroll to the bottom and find *technologies* related to (likely hosted on) the subdomain/ domain. Metrics related to tech stack include application servers, server side encryption (like [TLS](../../networking/protocols/TLS.md) and [SSL](../../networking/protocols/SSL.md)), Client side tech stack like [javascript](../../coding/languages/javascript.md), [PHP](../../coding/languages/PHP.md), scripting frameworks, etc.. [CDNs](../../www/CDNs.md), doctypes, [HTML](../../cybersecurity/bug-bounties/hackerone/hacker101/HTML.md), CSS, etc..
### [Threat Map](https://www.netcraft.com/threat-map/)
A global map showing incident types like [phishing](../../hidden/Sec+/24%%201%20Attacks,%20Threats%20&%20Vulnerabilities/1.1%20Social%20Engineering/phishing.md), malware, breaches, etc.. The free version is just a demo unfortunately :(.

> [!Resources]
> - [Netcraft](https://www.netcraft.com/tools/) 
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.