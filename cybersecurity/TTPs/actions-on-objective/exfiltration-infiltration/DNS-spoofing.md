
# DNS Spoofing/ Cacheing
DNS Spoofing is a technique where the attacker introduces *forged DNS* data into a [DNS](networking/DNS/DNS.md) resolver's cache. The aim is usually to force the resolver to *return an incorrect IP address* for a host-name lookup. This allows an attacker to *divert the traffic* for that hostname to their own malicious machine.
## Vs. DNS Hijacking
DNS hijacking is very similar to DNS spoofing because the end result is the same: the attacker has managed to *redirect queries* to a different, malicious domain. The difference b/w DNS Spoofing and DNS Hijacking is that the attacker *uses DNS records of the nameserver* rather than the Resolver's cache to poison the information.

> [!Resources]
> - [Cloudflare: DNS Security](https://www.cloudflare.com/learning/dns/dns-security/)