
# Web Proxy Automatic Detection
WPAD is a protocol in Windows environments which probes around the network looking for a *WPAD server*. WPAD servers host a [proxy](/www/proxy.md) configuration file, usually at the [DNS](/networking/DNS/DNS.md) address `wpad.domain.com`.
## Mechanism
WPAD uses both [DHCP](networking/protocols/DHCP.md) and DNS protocols to find the URL of the configuration file held by the WPAD server. The configuration file is used to determine if a specified URL *has a proxy* and what it is.
### Use
WPAD is used sometimes because it makes configuring all of the browsers in an organization much easier. Without WPAD, each browser in the organization would *have to be manually configured* w/ the same proxy policy.
#### Requirements:
For all browsers in an org to be given the same proxy policy, two things have to be present:
- Proxy Auto-Config standard (PAC): creates and publishes a single central proxy config file.
- WPAD standard: ensures that all browsers will find the config file.
## Security
*Most organizations don't have an existing WPAD host* so, when a DNS request is sent to the [domain controller](computers/windows/active-directory/domain-controller.md), no DNS record is returned. On Windows systems, when a DNS request to resolve to an IP fails *other protocols are used instead*. This includes [LLMNR](networking/protocols/LLMNR.md) and [NBT-NS](networking/protocols/NBT-NS.md), both of which are *vulnerable to [DNS poisoning](cybersecurity/TTPs/exploitation/injection/DNS-poisoning.md)* attacks.

> [!Resources]
> - [Wikipedia: WPAD](https://en.wikipedia.org/wiki/Web_Proxy_Auto-Discovery_Protocol)
> - [NopSec: Responder Beyond WPAD](https://www.nopsec.com/blog/responder-beyond-wpad/)

