---
aliases: [CIDR, classless inter-domain routing]
---
# Classless Inter-domain Routing
Method for allocating [IP-addresses](/networking/OSI/IP-addresses.md) and IP routing.

CIDR is a collection of Internet Protocol standards used to create unique identifiers for networks and individual devices. Facilitates unique packet transmission to specific devices.

## Traditional "Classful" Network Addressing:
Network Addressing used to work off a class-based system in which IPv4 ranges were split up into classes. Each class differed on network size (the number of networks vs the number of hosts the range could support).

### Class A:
First bit (most significant) is *always set to zero*, with the next 7 bits defining the network number. This range of IPs could accommodate 128 networks in total.

Covers IP addresses `1.X.X.X to 126.X.X.X`.

### Class B:
The range of all addresses which have their 2 most significant bits set to 1 and 0 respectively. Network address defined w/ the next 14 bits, leaving 16 bits total for numbering hosts on the network and a total of 65,536 addresses per network.

Covers addresses between `128.0.0.X to 191.255.X.X`

### Class C:
Range of all addresses w/ the first 3 most significant bits set to 1, 1, and 0 respectively. The next 21 bits defined the number of networks, leaving each network w/ 256 host addresses.

Covers addresses b/w `192.0.0.X to 223.255.255.X`

### Classes D and E:
Class D addresses had the first 4 most significant bits set to `1110` and Class E had the first 4 set to `1111`. Class D was used for *multicast addressing* while Class E was meant to be reserved for future use.

Class D: `224.0.0.0 to 239.255.255.255`
Class E: `240.0.0.0 to 255.255.255.254`

### IPv4 Exhaustion:
The class system extended the use of IPv4 but did not prevent its eventual exhaustion of address space.

In 1993 Classful IP Addressing was replaced with Classless Inter-Domain Routing (CIDR).

## CIDR:
- consists of #CIDR-blocks
	- allows #IP-addresses to be *dynamically allocated* 
		- allocated based on the requirement of the user and on certain rules
		- handled by the IANA (Internet Assigned Number Authority)

#CIDR-block 
- Contains IP addresses based on 3 simple rules:
	1. w/i the block, IP addresses allocated to the hosts should be *continuous*
	2. the size of the block should be to the power of 2 and be equal to the total number of IP addresses
	3. the size of the block mustt be divisible by the first IP address of the block

## CIDR Notation
- CIDR IP address notation: ```X.X.X.X/n```
	where ```X.X.X.X``` is the IP address and ```/n``` is the number of network bits
- Example:
	- CIDR notation: ```21.19.35.40/24``` 
		1st IP address is ```21.19.35.0```
		last is ```21.19.35.255```
		total cost is 256
		net mask is ``255.255.255.0``
- x68:
	- Every #IPV4 address has four octets of bits, separated by a period for a *total of 32 bits*
		- The left side of an address = the "network side"
		- the right side = the "host side"
	- Address in CIDR  notation = the network address followed by a slash and a number of bits.
		- ex: network address = 172.16.23.1
		- CIDR notation of address: 172.16.23.1/24
			- (24 = number of bits of the address which make up the network (left) half of the address)
			- since 24 / 8 = 3 then the first *three bytes* make up the network portion of the address (172.16.23)
				- the remaining *8 bits* belong to the host
			- SO:
				- the network address = ``172.16.23.0``
				- and the host address = ``0.0.0.1`` 
>[!Links:]
> [EDUCBA](https://www.educba.com/what-is-cidr/)
> [Wikipedia: Classful Networks](https://en.wikipedia.org/wiki/Classful_network)

