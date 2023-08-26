
# Connect-Back Persistence Technique
This technique is used by attackers to *get around [firewalls](/cybersecurity/defense/firewalls.md)* and establish persistence on a target. It also allows them to connect a target *back to their C2* via outgoing connections since these are *rarely blocked by firewalls*.
## Approaches
### Phishing
There are multiple ways an attacker can achieve a connect-back. Some approaches use [phishing emails](/cybersecurity/TTPs/delivery/phishing.md) to trick a target into allowing them through a firewall.
### [IP Address](/networking/OSI/IP-addresses.md) Attack
They can also "attack public IP addresses found on a server to update their C2 system"(?)(abusix.com)
## Mitigation

> [!Resources]
> - [Abusix: How Hackers Access Networks...](https://abusix.com/resources/abuse-desks/how-hackers-access-networks-using-backdoors/)