
# DNS Security
When [DNS](/networking/DNS/DNS.md) was designed, it was not designed w/ security in mind. Because of this, DNS comes with a lot of security implications and design limitations. This makes DNS *vulnerable to a lot of different attacks*.

Because the DNS system is so commonly used, securing it is difficult. It can't easily be swapped out for a different system, so protecting DNS and defending against DNS-based attacks is focused on mitigating its inherent vulnerabilities.
## Implications
DNS is a very vulnerable protocol in part b/c it was designed w/o considering security, but also because DNS traffic *tends to be treated as trustworthy*.
### Poor Design
DNS was invented without taking security of the protocol into account. For example, exploiting DNS used to be as easy as *guessing the transaction ID (TXID) of the request*. It used to be that this ID was used to track the request for a domain missing from the resolver cache. Each hop of the request through different Root and TLD servers, the TXID would be incremented.

So, an attacker could easily guess the TXID of the response and use that to craft a DNS response to the resolver's router.
![](/networking/networking-pics/dns-security-1.png)
This attack was finally mitigated by *randomly generated* TXIDs, however, the random number was stored in a 16-bit randomization key. Soon, hackers were able to exploit this by simply calculating the time window for a response to be received by the querying resolver, and sending as many queries as possible w/i that window.

Since there are only 65,536 possible values for the TXID, a hacker simply had to send as many malicious responses in the timeframe and there likelihood of guessing the right one increased.

Now, the TXID *as well as the port number* is randomized and combined into a 32-bit key, making attacks like [DNS Spoofing](../../cybersecurity/TTPs/actions-on-objective/exfiltration-infiltration/DNS-spoofing.md) (using the TXID) much harder to perform.
### Recent Vulns
While DNS is more secure than it used to be, it still has to be *implemented properly* by developers. A good example of poor DNS implementation is this [CoreDNS bug](https://github.com/coredns/coredns/issues/3547) in which the port and TXID were generated using a *non-cryptographically secure* randomization method in [Golang](/coding/languages/golang.md).

Because the `math.rand` function in Golang does not actually create an unpredictable value, an attacker would easily exploit this by predicting the transaction ID and perform DNS spoofing.
## Common Attacks
### DNS Spoofing/ Cache Poisoning
![DNS-spoofing](../../cybersecurity/TTPs/actions-on-objective/exfiltration-infiltration/DNS-spoofing.md)
### DNS Hijacking
DNS Hijacking is slightly different than [DNS-spoofing](../../cybersecurity/TTPs/actions-on-objective/exfiltration-infiltration/DNS-spoofing.md) because the attacker uses *DNS Records* rather than the Resolver's cache to redirect queries.
### DNS Tunneling
![DNS-tunneling](/cybersecurity/TTPs/c2/DNS-tunneling.md)
### NXDOMAIN Attack
An NXDOMAIN attack is a form of [denial of service](/cybersecurity/TTPs/exploitation/denial-of-service.md) where an attacker floods a DNS server with fraudulent requests *for records which don't exist*. This denies the flow of *legitimate traffic* and fills the resolver's cache w/ junk requests.
### Others:
- Phantom Domain attack
- Random Subdomain attack
- Domain Lock-up
- [Botnet](../../cybersecurity/TTPs/c2/botnet.md) CPE attack
## DNSSEC
[DNSSEC](/networking/protocols/DNSSEC.md) is a security protocol which implements digital signing of data to ensure its validity.
![DNSSEC](/networking/protocols/DNSSEC.md)
## Other DNS Security
### Sinkhole Address
Also called "blackholing". One way to use DNS to secure a network is to set up a sinkhole address. This address is used *whenever a device on the network tries to connect to a known malicious address.* When that happens, we can route them instead to our *sinkhole address.* At the sinkhole address we have monitoring turned on so we can see *how many devices and which devices* attempted to connect to malicious sites.

This can be used to *detect malicious activity* and *stop infected devices* from connecting back to their [C2](../../cybersecurity/TTPs/c2/C2.md) servers. Additionally, if we see an internal device attempting to connect to a malicious address, we can intervene and get that device quarantined off the network.

This is also effectively content filtering. 

> [!Resources]
> - [Unit 42: DNS Vulnerabilities](https://unit42.paloaltonetworks.com/dns-vulnerabilities/)
> - [Cloudflare: DNS Security](https://www.cloudflare.com/learning/dns/dns-security/)
> - [CoreDNS GitHub: Issue 3547, CVE-2019-19794](https://github.com/coredns/coredns/issues/3547)
> - [Professor Messer](https://www.youtube.com/watch?v=Nj_VF6tuBpw&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=111)
 
