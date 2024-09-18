
# Network Segmentation
Segmentation can be done physically, logically, or virtually using either devices, VLANs, or virtual networks. Segmentation can increase performance (especially for high-bandwidth applications), improve security by isolating users & sensitive information, and satisfy mandated compliance standards (like PCI).
## Security
### Micro-segmentation
Dividing the network into small, isolated segments. Helps to contain and limit the impact of security breaches.
### [Zero Trust](../../hidden/Sec+/Fundamentals/zero-trust.md)
### Least Privilege
Granting the least amount of privilege and access required for users and other systems to perform their functions.
### Multifactor Authentication (MFA)
### Continuous Monitoring
## Access Methods
### Physical Segmentation
Physical network devices are separated via "air gaps" (they're not connected by cables *at all*). This usually also includes consolidating services or servers/ databases etc. to one device or the other. I.e. with two separate switches, switch B might be connected to every device related to web services, while switch B is connected to every device related to databases and their servers. But switch A and switch B *are not connected at all* and have an air gap between them. This prevents any mixing of unrelated data.
![](../networking-pics/Pasted%20image%2020240710155214.png)
#### Disadvantages
Because we are using separate devices to provide physical segmentation, each device has to be *separately maintained*, which includes:
- separate updating
- separate power supply
- separate maintenance
Additionally, most enterprise capable switches come with *a lot of interfaces*. If we're using them to physically segment a network, then it's likely we're not utilizing most of the interfaces, which means a lot of money was spent on the switch *to not use it to its full capabilities*.
### Logical Segmentation & [VLANs](VLANs.md)
With this configuration, the same separation is achieved between segments, but its done *logically within the same [network-layer](../OSI/3-network/network-layer.md) device*. The only way two VLANs can communicate is through another layer 3 device such as a [router](../OSI/3-network/router.md).
![](../networking-pics/Pasted%20image%2020240710155734.png)
### Screened Subnet (DMZ)
A screened subnet is a segmented-off network which adds additional security by redirecting public access away from the internal network. Usually done with the help of a [firewall](../../cybersecurity/defense/firewalls.md). When public traffic from the internet hits the firewall, it redirects that traffic to the screened subnet (or DMZ/ de-militarized zone) so it doesn't access the internal network.
![](../networking-pics/Pasted%20image%2020240710161235.png)
### Extranet
Similar to a DMZ, an extranet is a segmented network (forwarded to via a firewall) which is used as *private network access for partners* (vendors, suppliers, etc.). 

The major difference b/w an extranet and a DMZ is that an extranet *requires some kind of authentication*, so only authorized users can access it.
![](../networking-pics/Pasted%20image%2020240710161422.png)
### Intranet
This is a *private network* which is *only available internally*. It's usually configured to only be accessible *by employees* with no external access. 

Employees usually access the intranet via other internal, site-specific networks (which they're already connect to) or [VPN](VPN.md).
![](../networking-pics/Pasted%20image%2020240710161818.png)
### [VPNs](VPN.md)
### [Proxy](proxy.md) Servers
Device which *sits between end users and the internet*. Facilitates *communication on behalf of the user*. It functions by forwarding requests from the client/ user to servers on the internet and returns their responses back to the user. Basically serves as a *gateway*. 
### Load Balancers
device or software application that distributes incoming network traffic across multiple servers to ensure no single server bears too much load.
## Traffic Flow
Becomes important in large networks with many devices, all of which are segmented into different networks. For example, in a data center which is hosting a very large network, traffic flow, *or the direction in which data b/w devices is flowing* becomes important.
![](../networking-pics/Pasted%20image%2020240710162740.png)
### North-South Traffic
This is the flow of data/ traffic which is either *inbound or outbound* (ingress and egress to outside devices) to the data center. The data is mostly coming from *unknown and/or untrusted sources*, so the security implications and configuration is different than it would be for East-West traffic.
### East-West Traffic
This is traffic flowing b/w devices *within the same data center*. In this context, multiple segmented networks are being hosted in the same data center and they are likely being used by different orgs, services, users, etc.. It's important to keep track of who is trying to access what and from where, and where traffic needs to be sent/ routed to.

Because E/W traffic is b/w devices within the same data center, the response times between them are *very fast*.
> [!Resources]
> - [Professor Messer](https://www.youtube.com/watch?v=MiIzrykpaBk&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=108)