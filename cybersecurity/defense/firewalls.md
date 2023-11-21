
# Firewalls
Device w/i a network responsible for determining what traffic can enter and exit. Can be hardware or software.
## Configuration Factors:
Firewalls use packet inspection to determine:
- Where is the traffic *coming from* (has the firewall been configured to deny traffic from specific sources)?
- Where is the traffic *going to* (has it been configured to deny traffic from going to a specific network)?
- What*port is the traffic for* (has it been configured to deny traffic destined for a specific port)?
- What *protocol* is the traffic using (has it been configured to deny traffic which is [UDP](/networking/protocols/UDP.md)/ [TCP](/networking/protocols/TCP.md) or both?)
## Types/ Categories:
### Stateful
Stateful firewalls examine *the entire connection* instead of a single packet from a connection. These types of firewalls tend to be *resource heavy* & if the one packet is found to be bad *the entire connection is blocked.*
### Stateless
Stateless firewalls compare *individual packets against a set of static rules* to decide if ea packet is acceptable or not. If one packet from a device is bad, *the entire device will not be blocked*.

This type of firewall uses *fewer-resources*. However, they are considered 'dumb' because they're *only as effective* as the set of rules they follow. So, if one bad packet doesn't fit the specified rules *it will not be blocked*.
#### Security
Stateless firewalls are easier to exploit using [DDoS](/cybersecurity/TTPs/exploitation/denial-of-service.md).

> [!Resources]
> - [NetScout: Why DDoS Attacks Against Stateful... ](https://www.netscout.com/sites/default/files/2021-10/SECWP_020_EN-2101%20-%20Enemy%20of%20the%20State.pdf)
