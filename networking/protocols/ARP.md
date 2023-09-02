---
aliases: [ARP, address-resolution-protocol]
---
# Address resolution protocol
ARP is a [layer 3](/networking/OSI/network-layer.md) protocol which resolves a known, destination [IP Address](/networking/OSI/IP-addresses.md) into a [MAC Address](/networking/OSI/MAC-addresses.md).

This protocol uses an *ARP lookup table* to associate IP addresses on a network to [MAC Addresses](nested-repos/PNPT-study-guide/PEH/networking/MAC-addresses.md). While ARP tables are associated w/ MAC addresses, it is layer 3 devices (like routers) which create the table. Layer 2 devices (switches/ hubs) are not aware of ARP tables. 

When a host wants to find the MAC address attached to a destination IP address, it sends out an *ARP Request* to all other L3 devices on the network. If one of the devices has the answer in their ARP table, it will respond to the request with the MAC Address listed w/ the specific IP Address in its table.

>[!links]
> [Geeks for Geeks: ARP in Wireshark](https://www.geeksforgeeks.org/arp-in-wireshark/)
> [Cisco: Networking Tables](https://community.cisco.com/t5/networking-knowledge-base/network-tables-mac-routing-arp/ta-p/4184148)

