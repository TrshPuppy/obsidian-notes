---
aliases:
  - tunneling
  - deep packet inspection
  - DPI
---
# Tunneling thru Deep Packet Inspection
[_Deep packet inspection_](https://en.wikipedia.org/wiki/Deep_packet_inspection) (DPI) is used to monitor traffic *based on a set of rules* and is often used on the *perimeter* of a network. Deep packet inspection is useful for *detecting indicators of compromise* (IOCs). Devices which implement deep packet inspection are usually configured to *only allow specific network [protocols](../../PNPT/PEH/networking/ports-and-protocols.md)* to transverse in, through, and out of the network.

For example, a network admin could configure a deep packet inspection device to *terminate any outbound [SSH](../../networking/protocols/SSH.md) traffic*. Any connections via SSH would *fail* as a result.

For [penetration testing](../../cybersecurity/pen-testing/penetration-testing.md) this means our SSH-based [port redirection](../port-redirection-SSH-tunneling/README.md) techniques would be useless. Therefore, it's useful to know some Deep Packet Inspection tunneling techniques.
## Techniques:
1. [HTTP tunneling](HTTP-tunneling.md)
2. [DNS tunneling](DNS-tunneling.md)

> [!Resources] 
> - [_Deep packet inspection_](https://en.wikipedia.org/wiki/Deep_packet_inspection)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.