
# Physical Port Security
Init
## Broadcasts
Broadcasts are information sent from one device (via frames or packets) to every other device on the physical network. Every device *must inspect/ examine that communication*.

Broadcast traffic is *common* because there are many things which use broadcast to communicate. For instance, [routing](../../routing/routing.md) updates and [ARP](../../protocols/ARP.md) requests are sent via broadcast. This can *add up quickly* and bog down a network. Additionally, *some of this traffic can be malicious*.
### Broadcast domain
Broadcasts can be *limited in scope* by a broadcast domain. For example, a [VLAN](../../design-structure/VLANs.md) is a broadcast domain
### Broadcast Storm Control
Used by [switches](../2-datalink/switches.md) to control broadcasts by *limiting the number of broadcasts per second*. This can be use to improve security by controlling *multicast and unknown unicast* traffic. 

Configured w/ specific values and percentages, or a *change in normal traffic patterns*. For example, if the switch monitoring the traffic notices an increase in broadcast traffic over a short period of time, it can *block that traffic*.
## Loop Protection
### What is a loop
Looping happens when you connect two [switches](../2-datalink/switches.md) together. Since there is no counting mechanism in the [MAC-layer](../2-datalink/MAC-layer.md), they'll *send traffic back and forth indefinitely*. This is an *easy way* to bring down an entire network (but is also easy to resolve).
### STP
**Spanning Tree Protocol (802.1D):** 
![STP](../../protocols/STP.md)
## [DHCP](../../protocols/DHCP.md) Snooping
Another security issues w/ ports and switches is that someone could *plug in a DHCP* server to an interface. This type of device should be ignored/ not allowed to handle DHCP and issue IP addresses to devices on the network. 

Fortunately, most switches have built-in [firewall](../../../cybersecurity/defense/firewalls.md) software which can do DHCP Snooping. w/ DHCP snooping, the switch is configured to trust specific devices, like routers, switches, and DHCP servers, (via trusting their interface), and then *not trusting* other interfaces. 
### Mechanism
The switch listens to the traffic on all interfaces and if it *sees a DHCP packet* from an interface *that is not trusted*, then it will add that interface to its list of untrusted interfaces. Any DCHP traffic coming from that interface will  not be allowed to travel to other devices on the network.
## MAC Filtering
Allows the admin of the device to allow and/or disallow traffic based on [MAC address](../../../PNPT/PEH/networking/MAC-addresses.md) (the physical hardware address).
### Issue
Because this is layer 2, there is no way to obfuscate *the MAC addresses* connected to the network. So, if someone connects to the network, they can simply listen to the traffic and get an entire list of all of the MAC addresses, then just *spoof one to gain access*.

> [!Resources]
> - [Professor Messer](https://www.youtube.com/watch?v=S_6ri7QM_Rc&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=110)
