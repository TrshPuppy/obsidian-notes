---
aliases: [virtual-private-network, VPN]
---
# Virtual Private Network
Allows devices on separate networks to communicate securely.
- creates a designated oath b/w each other over the internet
	- known as a #VPN-tunnel
- devices connected to ea other via this tunnel are part of their own private network

Below:
The devices connected via VPN on network 3 are still part of network 1 and network 2 respectively.
- network 3 is a private network b/w them which only devices connected to the VPN can communicate through
![[Pasted image 20230211180034.png]]
-TryHackMe.com

## Benefits:
- networks in different geographical locations can connect
- connection is ==private==
	- VPNs use #encryption to protect data
		- data can only be decrypted and understood by the devices on the VPN
- anonymity
	- without a VPN your traffic can be seen by #ISPs etc.
	- Only as private as other devices on the network respect it
		- (a VPN which logs your data/ history is basically like not using a VPN at all)
	- Ex: good for journalists reporting from other countries where freedom of speech is limited

## Technologies:
1. #PPTP / Point to Point Tunneling Protocol
	- Uses [[TCP]] #port-1723 for remote access over the internet
	- Doesn't require a router if initiated by the #client 
	- Fastest of the protocols 
	- easy to set up
	- Not as secure (uses weak encryption)
- #PPP / Point to Point Protocol
	- A protocol which covers multiple computer communications protocol
	- used by PPTP for authentication and encryption of data
- #IPSec / Internet Protocol Security
	- encrypts data using the existing #IP framework
	- more difficult to set up
	- strong encryption
	- supported by most devices

## TYPES:
- #remote-access:
	- Connecting a device to a LAN (local area network)
	- externally
- #site-to-site:
	- connecting two networks which are separate (geographically etc.)
	- #extranet-based : 
		- two networks connect, which are not part of the same organization

## Security:
- remote access is authenticated and uses encryption
	- confidentiality: VPN connections ensure that data even at packet level is encrypted (packet sniffing)
		- not all VPN protocols provide encryption
	- authentication: sender is authenticated
	- integrity: prevents tampering w/ transmitted data

>[!links]
>https://en.wikipedia.org/wiki/Virtual_private_network
>PPTP:
>https://www.purevpn.com/what-is-vpn/protocols/pptp
>PPP:
>https://www.techtarget.com/searchnetworking/definition/PPP
