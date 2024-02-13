
# DNS Tunneling
In [DNS](networking/DNS/DNS.md) tunneling, an attacker encodes data they want to deliver in (such as malware) or exfiltrate in DNS queries. A lot of organizations are vulnerable to this attack because *DNS traffic outwards is assumed to be trustworthy* and so is often left *unmonitored*, even by the [firewall](cybersecurity/defense/firewalls.md).
## Methodology
In order to perform DNS tunneling, the attacker normally *already has access to the network*. The objective is to move data, whether in or out, without being detected. This is usually done using a *client-server* model where the attacker controlled domain is the server and the infected computer is the client. In order to do this, some things have to already be in place:
1. The attacker has a registered domain in their control
2. The attacker, or their malware, has already compromised the network and infected a trusted machine.
3. The infected machine is behind the firewall (since DNS queries are *allowed out by default*)
4. The DNS resolver relays the request for the attacker's IP address to the attacker's domain

> [!Resources]
> - [BrightSec: What is DNS Tunneling](https://brightsec.com/blog/dns-tunneling/#how-it-works)
> - [Palo Alto Networks: What is DNS Tunneling](https://www.paloaltonetworks.com/cyberpedia/what-is-dns-tunneling)
> - [Cloudflare: DNS Security](https://www.paloaltonetworks.com/cyberpedia/what-is-dns-tunneling) 