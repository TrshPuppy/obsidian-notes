
# Routing Tables
Routing tables are tables of [IP addresses](/networking/OSI/3-network/IP-addresses.md) maintained by [L3](/networking/OSI/3-network/network-layer.md) devices like routers and L3 switches. Routing tables are basically data structures which routers refer to to determine the path to transfer packets from a source IP address to a destination IP.

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

> [!Resources:]
> - [Wikipedia: Routing tables](https://en.wikipedia.org/wiki/Routing_table)
> - [Cysec Guide: Linux routing table](https://cysecguide.blogspot.com/2017/12/linux-routing-table.html)
> - [Wikipedia: IS-IS](https://en.wikipedia.org/wiki/IS-IS)


