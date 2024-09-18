
# Routing
Routing is a [layer 3](../OSI/3-network/network-layer.md) function in which the path to specific devices on a network is selected based on certain characteristics. In general, the most efficient path between two devices is preferred. Routing paths are saved in [routing tables](routing-table.md) in network devices.
## Types of Routing:
### Static
In static routing, the routing tables are *manually configured* on the [routers](../OSI/3-network/router.md). The routes do not changes and they *don't adopt changes* unless explicitly told to. Static routing is usually used in networks with a simple [topology](../design-structure/topology.md).
### Dynamic
Dynamic routing uses Dynamic routing protocols which enables routing tables to *automatically update their routing information* based on the current network topology. Routers using dynamic routing *communicate with each other* to update their own tables.

Some examples of dynamic protocols include:
- OSPF
- EIGRP
- BGP
### Default Routes
Default routes, also called the *Gateway of Last Resort* is a route that *matches all packets which don't match any specific routes* in the tables. When a router receives a packet it doesn't have a routing entry for, it *forwards it to the default route*. 

These routes are often used to direct packets to the internet and serve as a catch all. 
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

> [!Resources]
> - [Cloudflare: IP Routing](https://www.cloudflare.com/learning/network-layer/what-is-routing/)
> - [Wikipedia: Routing Info. Protocol](https://en.wikipedia.org/wiki/Routing_Information_Protocol)
> - [Wikipedia: Border Gateway Protocol](https://en.wikipedia.org/wiki/Border_Gateway_Protocol)
> - Internship learning material

