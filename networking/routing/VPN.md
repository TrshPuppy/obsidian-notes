
# Virtual Private Network
Allows devices on separate networks to communicate securely by creating a designated path (VPN tunnel) b/w each other over the internet. Devices connected to ea other via this tunnel are part of their own private network.
## Diagram:
The devices connected via VPN on network 3 are still part of network 1 and network 2 respectively. Network 3 is a private network b/w them which only devices connected to the VPN can communicate through.
![](/networking/networking-pics/VPN-1.png)
> [TryHackMe](https://tryhackme.com/room/extendingyournetwork)
## Benefits:
### Remote connections
Networks in different geographical locations can connect.
### Privacy
The connection is *private* because VPNs use encryption to protect the data. The data can only be decrypted and understood by the devices on the VPN.
### Anonymity
Without a VPN your traffic can be seen by ISPs, etc. and is only as private as other devices on the network treat it. A VPN which logs your data/ history is basically like not using a VPN at all.

A good example of the importance of anonymity is journalists reporting from other countries where freedom of speech is limited.
### Security
While not all VPN protocols provide encryption the ones that do help to protect against [packet-sniffing](/cybersecurity/TTPs/packet-sniffing.md). Users on the VPN are also authenticated. Additionally, the protocols protect against tampering with transmitted data which ensures data-integrity.
## Technologies:
### Point to Point Tunneling Protocol (PPTP)
Uses [TCP](/networking/protocols/TCP.md) port 1723 for remote access over the internet. This is the fastest of the protocols and doesn't require a router if initiated by the client.

It is easy to set up but is not secure because it uses weak encryption.
### Point to Point Protocol (PPP)
A protocol which covers multiple computer communications protocol. It's used by PPTP for authentication and encryption of data.
### Internet Protocol Security (IPSec)
Encrypts data using the existing IP framework. This protocol is more difficult to set up but provides strong encryption and is still supported by most devices.
## Types:
### Remote Access VPN
Used to connect a device to a LAN (local area network) externally.
### Site to Site
Connects two networks which are separate (geographically etc.). Considered *extranet-based*

> [!Resources]
> - [THM: Extending your Network](https://tryhackme.com/room/extendingyournetwork)
> - [Wikipedia: VPN](https://en.wikipedia.org/wiki/Virtual_private_network)
> - [Pure VPN: PPTP](https://www.purevpn.com/what-is-vpn/protocols/pptp)
> - [PPP](https://www.techtarget.com/searchnetworking/definition/PPP)
