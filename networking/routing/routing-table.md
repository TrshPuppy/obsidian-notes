
# Routing Tables
Routing tables are tables of [IP addresses](/networking/OSI/IP-addresses.md) maintained by [L3](/networking/OSI/network-layer.md) devices like routers and L3 switches. Routing tables are basically data structures which routers refer to to determine the path to transfer packets from a source IP address to a destination IP.

A routing table includes the following things:
1. *Destination Network:* represented by a destination IP Address and its [subnet mask](/PNPT/PEH/networking/subnetting.md).
2. *Next Hop:* For each destination network, the routing table specifies the IP address for the next router/ network interface to which the outgoing packet should be sent. The next hop can either be directly connected to the router or a remote router.
3. *Metric/ Cost:* Each entry in the routing table also has a metric or cost associated with it. This represents the efficiency of the route each specific route. The packet will be sent *via the route with the lowest metric.* Efficiency is measured in: 
	- time
	- latency
	- bandwidth
	- delay
	- hop count
4. *Default Match:* If a router can't find a route for a given destination IP in its table, then the packet can be sent via the default route. This route usually has a destination IP of `0.0.0.0/0` and points to a default gateway.

Routing tables can also include additional fields which help refine the the selection of a packet's path:
- *Quality of Service:* A flag which indicates whether the path is active. `U` is normally used to signify the path is active/ the route is up.
- *Filtering Criteria:* Access control lists associated w/ the router.
- *Interface:* An example of an interface is `eth0` which signifies the first Ethernet card, or `eth1` which signifies the second Eth. card.

Example of a routing table when using the `netstat -rn` command:
![](/networking/networking-pics/routing-table-1.png)
> [Cysec Guide: Linux routing table](https://cysecguide.blogspot.com/2017/12/linux-routing-table.html)
## Routing Protocols: 
Routing protocols are protocols which routers use to communicate with each other about the topology of their networks. These protocols allow routers to share and update their own information on how data should be routed between sources and destinations.

One router alone only has information in its tables related to networks and devices directly attached to it. W/ routing protocols, this information can be shared among immediate neighbors first, and then throughout the network, allowing all the routing devices to gain a topology of their network.

Because routing protocols *and routing tables* are dynamic, the routes and paths between devices can be updated. This contributes to the local network's and larger internet's *fault tolerance* because the network can adapt to changing conditions such as lost connections or obstructions.

This also allows networks and the internet to increase their availability despite connection losses across different links making up the network.
### Examples of Routing Protocols:
#### [IS-IS](/networking/protocols/IS-IS.md) (Intermediate System to Intermediate System): 
Is an interior gateway protocol used in the [data-link-layer](/networking/OSI/data-link-layer.md) of the OSI to help move data throughout a *local domain or network*.
#### [OSPF](/networking/protocols/OSPF.md) (Open Shortest Path First):
OSPF is a *link-state* protocol which is designed to find the best path for routing packets through a single autonomous system.
#### [RIP](/networking/protocols/RIP.md) (Routing Information Protocol):
One of the oldest routing protocols. Uses the *hop count metric* to dictate routing. In RIP, hop counts above 15 are not allowed, which limits its use as a protocol on larger networks, but also prevents routing loops.
#### [BGP](/networking/protocols/BGP.md) (Border Gateway Protocol):
BGP is an *exterior* gateway protocol. It makes routing decisions based on paths, network policies, and rule-sets configured for a network.

> [!Resources:]
> - [Wikipedia: Routing tables](https://en.wikipedia.org/wiki/Routing_table)
> - [Cysec Guide: Linux routing table](https://cysecguide.blogspot.com/2017/12/linux-routing-table.html)
> - [Wikipedia: IS-IS](https://en.wikipedia.org/wiki/IS-IS)
> - [Wikipedia: Routing Info. Protocol](https://en.wikipedia.org/wiki/Routing_Information_Protocol)
> - [Wikipedia: Border Gateway Protocol](https://en.wikipedia.org/wiki/Border_Gateway_Protocol)

