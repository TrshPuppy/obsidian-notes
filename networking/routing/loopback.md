
# Loopback IP Addresses
The loopback [CIDR](/networking/routing/CIDR.md) block, `127.0.0.0/8` is a reserved collection of addresses on a local machine. It mocks the [TCP/IP](/networking/protocols/TCP.md) server or TCP/IP client on the same machine.

`127.0.0.1` is a network address which can be used to refer to the current machine you're on. It is also called the *localhost* or *loopback address*.

![](/networking/networking-pics/loopback-1.png)
>	[Geeks for Geeks](https://www.geeksforgeeks.org/what-is-a-loopback-address/)
## Steve:
**Let's say this is all happening on the network `192.168.0.0/24`:**

Each computer's OS ships  w/ a *TCP/IP stack* which understands the TCP protocol. When any service/program wants to access a network resource via TCP/IP if goes through the IP Stack.
### Network Interface:
"Network Interface" usually refers to the computer's network card. Each computer has a Network Interface Card (NIC) (either for ethernet or wifi) which knows how to connect the device to internet. The NIC is allocated an [IP Address](/networking/OSI/IP-addresses.md) (usually by a router). The NIC also knows its device's [MAC Address](/networking/OSI/MAC-addresses.md). 

In this example, the computer's NIC's IP address is **`192.168.0.5`**.
### [Virtual Private Networks](/networking/routing/VPN.md):
A VPN creates a *virtual network interface* w/ a *virtual IP address* and *virtual MAC address*.

The VPN's network in this example is **`10.0.0.12/8`** with a gateway address of **`10.0.0.1`**.
### Routing Journey:
![](/networking/networking-pics/IP-routing-steve.png)
>	Drawing by Steve

The computer knows how to route traffic because the OS *has its own [routing table](/networking/routing/routing-table)*. Each entry in the routing table is a destination address as well as its [subnet mask](nested-repos/PNPT-study-guide/PEH/networking/subnetting.md), gateway, next hop, etc..
#### Browser requests a domain:
If the web browser running on the computer requests `google.com`, the browser asks the IP stack. The IP stack needs to resolve the domain name (`google.com`) to an IP address, so it needs to find [DNS](/networking/DNS/DNS.md) server.

To find the DNS server, the IP stack consults the OS's routing table to get the IP address of the router (which knows the route to the nearest DNS server). The IP address of the router is `192.168.0.1`.
#### IP Stack requests router's MAC address:
An [ARP](/networking/protocols/ARP.md) request is sent: "who on this network has the IP `192.168.0.1`?" The ARP packet travels around the local network, being sent to every device until one responds with the answer (a MAC address). 

When the router receives the ARP packet it responds with: "`00:00:00:00:00:03` is the MAC address of the IP `192.168.0.1`". A new entry is made in the ARP table:
```
- IP: 192.168.0.1
- MAC: 00:00:00:00:00:00:03
```
#### DNS request sent to DNS server:
Now that the IP stack knows the MAC address of the router, a DNS request to resolve `google.com` can be sent to the router (`192.168.0.1`). The router forwards the request to whatever DNS server is knows (outside the network) and receives a response: "the IP address for `google.com` is `8.8.8.8`".

The response from the DNS server is forwarded from the router to the IP stack, and then to the browser. Now the browser can *send packets to `google.com `using `8.8.8.8`*.
#### Browser wants to send packets to Google:
Once the browser has the IP address, it tells the IP stack that it wants to send packets to `8.8.8.8`/ `google.com`. It sends a packet with a destination and source IP:
```
- Dest IP: 8.8.8.8
- Src IP: 192.168.0.5
```
Even though we've resolved `google.com`, *`8.8.8.8` does not exist in the routing table yet*.
#### Network Address Translation:
Routers can perform Network Address Translation (NAT). When an IP address doesn't exist in the routing table, a request is sent *via the default route in the table* (`192.168.0.1`).

The router will "pretend" to send the packet to `8.8.8.8` but really just sends it to the next public router it has a route to. If the router's *public IP* is `5.5.5.5`, it will send a packet out with the Dest IP of `8.8.8.8` and Src IP of `5.5.5.5`.

>	**IMPORTANT:** the router will have a *private* IP address known within the network (`192.168.0.1`) and a *public IP* address known to networks outside of the local network (`5.5.5.5`).

![](/networking/networking-pics/IP-routing-steve-2.png)
>	Steve

The packet will travel from router to router in the ISP's network (hop) until it finds a router who knows a route to `8.8.8.8`. The router which knows will send the routing information back to the original router (`5.5.5.5`) which can then add the new route in its routing table.
#### Packets from browser sent to Google:
Now that the routing table has the IP address and route (and domain resolution) for `google.com`, the IP stack can help the browser send and receive packets to Google.
### Loopback and Localhost:
When the browser asks to communicate w/ `127.0.0.1` (the device's localhost/ loopback address), the browser doesn't know that it's requesting a *special* IP address.

The entire routing process is different in this case as compared to the browser's request for `google.com`:
#### Browser asks IP stack for `127.0.0.1`:
The browser sends an [HTTP](www/HTTP.md) `GET` request to the IP stack, looking for the IP `127.0.0.1`. The request will also use TCP so port 80 will be added to the request.

The IP stack *knows that `127.0.0.1`* is a special case. It basically says "This is me so I'm gonna *loop it back* to myself". Then it checks to see if anything is listening on port 80.

Within the localhost network, a localhost web server will be listening on port 80. So the IP stack will route the browser to this loopback/ localhost webserver and the browser can't tell the difference.

Unlike the Google example *no packets, network interfaces or actual networking was involved.*

>[!Resources:]
> - [Geeks for Geeks: What is a Loopback Address](https://www.geeksforgeeks.org/what-is-a-loopback-address/)
> - My friend Steve
