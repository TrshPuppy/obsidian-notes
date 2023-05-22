# IP Addresses

## IPv4 vs IPv6:
Possible amount of IP addresses = 32 bits (2^32) = about 4 billion addresses. _We have already run out of addresses using IPv4._

### IPv6:
Instead of using 32 bits to create IP addresses, we use hexadecimal notation to create 128 bits (2^128) for addresses (a much larger amount which we will likely never use up).

### Network Address Translation:
The process of re-mapping an IP address space into another by modifying the address information in the IP Header of packets while they are still in transit. NAT has been a solution to conserving address space in [IPv4 Exhaustion](/networking/routing/CIDR.md). This is because one IP address of a NAT Gateway can be used for entire _private network._

Example: Think of your public IP on your router. It is your public-facing IP address, yet every device on your network has its own individual address as well.

![](/PNPT-pics/IP-addresses-1.png)

-[Wikipedia](https://en.wikipedia.org/wiki/Network_address_translation)

### CIDR:
In 1993 the Class system of IP Addressing was replaced with [Classless Inter-Domain Routing](/networking/routing/CIDR.md) which is a collection of protocols which define standards used to create unique identifiers for networks and individual devices.

It allows IP addresses to be _dynamically allocated_ based on the requirement of user and specific rules.

> [!Resources]
> [Wikipedia: Network Address Translation](https://en.wikipedia.org/wiki/Network_address_translation)
> My own previous notes:
> > Local path (won't work on GitHub): [IP Addresses](/networking/OSI/IP-addresses.md)
> > GitHub path: [IP Addresses](https://github.com/TrshPuppy/obsidian-notes/blob/main/networking/OSI/IP-addresses.md)
