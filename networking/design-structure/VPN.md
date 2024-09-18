
# Virtual Private Network
Allows devices on separate networks to communicate securely by creating a designated path (VPN tunnel) b/w each other over the internet. Devices connected to ea other via this tunnel are part of their own private network. The traffic is usually [encrypted](../../computers/concepts/cryptography/symmetric-encryption.md) and travels over public networks.
## Design
### Concentrator
The concentrator is a device which is responsible for encrypting and decrypting the traffic on a VPN. It is usually a standalone device but can also be *integrated into a [firewall](../../cybersecurity/defense/firewalls.md)*. 

Concentrator are used on either end of the connection. Concentrators on *client* machines are usually software-based and built into the [OS](../../computers/concepts/operating-system.md). The server-side concentrator usually *sits in front of the network the client is trying to tunnel into* remotely. 
### Full Tunnel
With a full tunnel VPN, a tunnel is created between the VPN concentrator and the client. If the client wants to communicate with *servers outside the tunnel*, they have to send their communication to the concentrator first, which *then forwards the traffic to the external server*.
![](../networking-pics/Pasted%20image%2020240712105439.png)
### Split Tunnel
With split tunnel VPNs an *administrator* can configure the tunnel so that some communication from the client has to be forwarded via the concentrator, and some can go directly from the client to the external server.
![](../networking-pics/Pasted%20image%2020240712105702.png)
In this configuration, the direct connection made b/w the client and the external resource *is the 'split tunnel'*.
### Site to Site
With a site to site connection each peer (usually two remote networks) have a [firewall](../../cybersecurity/defense/firewalls.md) between them and the *firewalls manage the encrypted connection*. This is usually done w/ firewalls that have *concentrators integrated into them*.
![](../networking-pics/Pasted%20image%2020240712110047.png)
#### LT2P
**Layer 2 Tunneling Protocol**: Used w/ site to site VPN systems. L2TP is used to connect networks as if *they were connected over [layer 2](../OSI/2-datalink/MAC-layer.md)* but they're actually connected over [layer 3](../OSI/3-network/network-layer.md). `port 1701`

Commonly used in conjunction w/ [IPsec](../protocols/IPsec.md) where L2TP is used *for the tunnel* and IPsec is used *for the encryption*.
## Diagram
The devices connected via VPN on network 3 are still part of network 1 and network 2 respectively. Network 3 is a private network b/w them which only devices connected to the VPN can communicate through.
![](/networking/networking-pics/VPN-1.png)
> [TryHackMe](https://tryhackme.com/room/extendingyournetwork)
## Benefits
### Remote connections
Networks in different geographical locations can connect.
### Privacy
The connection is *private* because VPNs use encryption to protect the data. The data can only be decrypted and understood by the devices on the VPN.
### Anonymity
Without a VPN your traffic can be seen by ISPs, etc. and is only as private as other devices on the network treat it. A VPN which logs your data/ history is basically like not using a VPN at all.

A good example of the importance of anonymity is journalists reporting from other countries where freedom of speech is limited.
### Security
While not all VPN protocols provide encryption the ones that do help to protect against [packet-sniffing](/cybersecurity/TTPs/packet-sniffing.md). Users on the VPN are also authenticated. Additionally, the protocols protect against tampering with transmitted data which ensures data-integrity.
## Technologies
### Secure Socket Layer ([SSL](../../hidden/Sec+/25%%203%20Implementation/3.1%20Secure%20Protocols/SSL.md))
This type of VPN is common and *easy to set up and manage*. This is because it uses SSL, a very common protocol, which communicates over `port 443`. `port 443` is used so commonly that this type of VPN almost never has *issues with firewalls* and is already open on nearly every network. Additionally, it doesn't require the use of large VPN clients which can be complex to set up and manage.
#### Authentication
Authentication on this type of VPN is usually very simple, sometimes only requiring a user name and password, maybe MFA, in order to use the concentrator. It doesn't require implementing more complex authentication technologies like digital certificates or shared password (like [IPsec](../../hidden/Sec+/25%%203%20Implementation/3.1%20Secure%20Protocols/IPsec.md)).
#### Running in Browser (HTML5)
SSL VPNs can run in the browser. VPN services which do this use *HTML5*. [HTML](../../cybersecurity/bug-bounties/hackerone/hacker101/HTML.md)5 includes API support including a web cryptography API. Since this is all handled in the browser *you don't have to install any VPN applications* in order to use the VPN. The only required thing is a browser *which supports HTML5*.
### Point to Point Tunneling Protocol (PPTP)
Uses [TCP](/networking/protocols/TCP.md) port 1723 for remote access over the internet. This is the fastest of the protocols and doesn't require a router if initiated by the client.

It is easy to set up but is not secure because it uses weak encryption.
### Point to Point Protocol (PPP)
A protocol which covers multiple computer communications protocol. It's used by PPTP for authentication and encryption of data.
### Internet Protocol Security ([IPsec](../../hidden/Sec+/25%%203%20Implementation/3.1%20Secure%20Protocols/IPsec.md))
Encrypts data using the existing IP framework. This protocol is more difficult to set up but provides strong encryption and is still supported by most devices.
## Types
### Remote Access VPN
Used to connect a device to a LAN (local area network) externally.


> [!Resources]
> - [THM: Extending your Network](https://tryhackme.com/room/extendingyournetwork)
> - [Wikipedia: VPN](https://en.wikipedia.org/wiki/Virtual_private_network)
> - [Pure VPN: PPTP](https://www.purevpn.com/what-is-vpn/protocols/pptp)
> - [PPP](https://www.techtarget.com/searchnetworking/definition/PPP)
> - [Professor Messer](https://www.youtube.com/watch?v=YFyt8aY8PfI&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=109)
 