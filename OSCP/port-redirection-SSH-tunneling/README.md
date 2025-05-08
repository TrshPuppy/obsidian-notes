---
aliases:
  - port redirection
  - SSH tunneling
---
# Port Redirection & SSH Tunneling
Most network [topologies](../../networking/design-structure/topology.md) are designed to ensure a network *is not flat*. Flat networks are insecure because each device on the network *has direct lines of communication* between them allowing them to communicate freely. In other words, *there are no limits* for how each device accesses another on the dame network.

In a flat network, once an attacker has access to a single host, *they can communicate with every other host* in the network freely. This makes flat networks much easier to compromise. 
## Segmentation
To avoid a flat network topology, most networks introduce *[segmentation](../../networking/design-structure/segmentation.md)* which breaks the network into smaller networks. Each smaller network is called a [subnet](../../PNPT/PEH/networking/subnetting.md), and each subnet contains a group of devices which usually share a specific purpose. 

Devices on a subnet are only granted *access to each other* and can only access devices outside of their subnet *when absolutely necessary*. This severely limits attackers *because compromising a single host does not grant them access to every other host* on the network. 

Network segmentation also usually comes with controls which *limit the flow of traffic* into and out of the subnets. Most network admins will use various devices like [firewalls](../../cybersecurity/defense/firewalls.md) to implement traffic control.
### Firewalls
On [Linux](../../computers/linux/README.md) machines, the [kernel](../../computers/concepts/kernel.md) has builtin firewall capabilities which can be configured via the `iptables` tool. On [Windows](../../computers/windows/README.md), the [_Windows Defender Firewall_](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/windows-firewall-with-advanced-security) serves this purpose. Hardware firewalls can also be physically placed in the network to filter traffic. 

Firewalls can be configured to drop unwanted inbound traffic as well as prevent malicious traffic from traveling *outbound* to other subnets/ networks. They can limit communication to specific [ports](../../networking/routing/ports.md) and hosts as well as to the wider internet in general. 

Most firewalls limit traffic via a set of rules past on [IP address](../../networking/OSI/3-network/IP-addresses.md) and/or port number which makes their functionality limited. Some more advanced firewalls can use [_Deep Packet Inspection_](https://en.wikipedia.org/wiki/Deep_packet_inspection) which monitors the contents of incoming and outgoing traffic.
## Port Redirection & Tunneling
As pen-testers (or attackers on an internal network), we need techniques to help us bypass network restrictions like firewalls. Port redirection and tunneling are two strategies we can use.
### Port Redirection
Port redirection is a broad term to describe different kinds of *[port-forwarding](../../networking/routing/port-forwarding.md)*. In port redirection we modify the flow of data by *redirecting packets from one [socket](../../networking/OSI/3-network/socket.md) to another*
### Tunneling
Tunneling refers to *encapsulating* one kind of data stream *within another*. For example, you could use a [SSH](../../networking/protocols/SSH.md) connection to transport [HTTP](../../www/HTTP.md) traffic. The result would be that from the outside, *only the SSH traffic is visible*. 

> [!Resources]
> - [_Windows Defender Firewall_](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/windows-firewall-with-advanced-security)
> - [_Deep Packet Inspection_](https://en.wikipedia.org/wiki/Deep_packet_inspection)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.