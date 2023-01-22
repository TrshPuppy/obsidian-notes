---
aliases: [CIDR, classless inter-domain routing]
---
# Classless Inter-domain Routing
Method for allocating #IP-addresses and IP routing.

[[TCP-IP]] (Internet Protocol)
- #CIDR = a collection of Internet Protocol standards used to create unique identifiers for networks and individual devices
	- facilitate unique #packet transmission to specific devices

## Traditional subnetting:
Five classes in #IPV4-addressing :
1. #Class-A addresses
	- first bit is considered and *always set to zero*
	- covers IP addresses between 1.X.X.X to 126.X.X.X
2. #Class-B addresses
	- first two bits considered: 
	- addresses between 128.0.0.X to 191.255.X.X
3. #Class-C addresses
	- first three bits
	- addresses b/w 192.0.0.X to 223.255.255.X.
4. #Class-D addresses
	- first four bits
	- 224.0.0.0 to 239.255.255.255
	- used for [[multicasting]]
5. #Class-E addresses
	- reserved for research and development
	- 240.0.0.0 to 255.255.255.254
*Classes aren't used anymore because they 'waste a lot of 32-bit address space'*

## [[CIDR]] is an alternative to traditional subnetting*
- consists of #CIDR-blocks
	- allows #IP-addresses to be *dynamically allocated* 
		- allocated based on the requirement of the user and on certain rules
		- handled by the IANA (Internet Assigned Number Authority)

#CIDR-block 
- Contains IP addresses based on 3 simple rules:
	1. w/i the block, IP addresses allocated to the hosts should be *continuous*
	2. the size of the block should be to the power of 2 and be equal to the total number of IP addresses
	3. the size of the block mustt be divisible by the first IP address oif the block

## #CIDR-notation
- CIDR IP address notation: ```X.X.X.X/n```
	where ```X.X.X.X``` is the IP address and ```/n``` is the number of network bits
- Example:
	- CIDR notation: ```21.19.35.40/24``` 
		1st IP address is ```21.19.35.0```
		last is ```21.19.35.255```
		total cost is 256
		netmask is ``255.255.255.0``
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
>[!links]
> https://www.educba.com/what-is-cidr/

