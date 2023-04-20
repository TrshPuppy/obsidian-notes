
x68 Jan 16:

## [OSI Reference Model](/networking/OSI/OSI-reference-model.md):
Data moves up and down these layers from physical to application and vice versa
- #physical-layer 
	- device
- #Data-link-layer
	- "Media Access Control"
	- flat topology
	- [ethernet-switching](/networking/OSI/ethernet-switching.md) (L2 switches)
		- have tables of ports w/ associated MAC-addresses
			- only one device per port (can be another switch)
		- assigns unique #MAC-addresses to devices
			- #MAC-addresses helps determine which port to send data thru
				- ex: Want to print taxes off a printer:
					- ea device has its own MAC-address (globally unique)
						- 128 bit identifier
						- used to be burned on (not ever supposed to change)
				- creates a flat network (can only grow horizontally)
				- As the tables get bigger (more devices attached) becomes less efficient
					- *Need to expand network in a different way* 
	- [ARP](/networking/protocols/APR.md): address resolution protocol
- #network-layer
	- handles IP addresses
	- Ex: 192.168.1.1
		- usually a router's IP address by default
		- ex computer on the network: 192.168.1.10
		- CIDR:
			- network address: 192.168.1.0/24
			- subnet mask: 255.255.255.0
				- the lower the CIDR number, the bigger the subnet
			- gateway: 192.168.1.1
	- Gateway/ DNS:
		- #traceroute
			- terminal command
				- uses ICMP
			- Ex: from ``192.168.3.190`` to printer at ``192.168.3.10``  
			- 
		- #dig 
			- ex: ``dig samcaldwell.net``:
				- returns DNS lookup info of address
				- can look from a specific IP's perspective:
					- ``dig @8.8.8.8 samcaldwell.net``
						- (perspective = Google)
		- 
- #transport-layer
	- [[UDP]] or [[TCP]] 
		- (there are others)
			- (can also handle IP)
- #session-layer 
- #presentation-layer 
- #application-layer
- Layer 8: user (not legitamate)

The internet:
- collection of routers
- [[BGP]] ("big goddamn problem")
	- "backbone" of internet (?)
	- there are several routes (through routers) you can use to get from one device to another
		- each hop between routers increases the cost
		- routers send advertisement messages to ea other which say what other routers they're connected to
		- 

IPs to remember:
- These are all #RFC-1918 (can be used for private networks) - only accessible for local networks
	- 192.168.1.0/24 : common, esp w/ home routers
	- 192.168.0.0/16 : 
	- 172.16.0.0/12 : 100,000 addresses
	- 10.0.0.0/8 : 16 million addresses
	- RFCx are internet standards
		- Rekhter et al 1996
- #network-address-translation
	- between internet and RFC 1918
	- ex: if your development environment is bound to 0.0.0.0
		- Can be accessed from anyone in local network
			- ex: Coffee cafe wifi
			- INSECURE
		- What to do instead:
			- bind environment to: ex: 192.168.1.99
				- inside laptop: [[loopback]] #loopback-addresses
					- ex: 127.0.0.0/8
						- keep environments within
						- ex: 127.255.0.1, 127.255.0.2 etc (loopback addresses)
	- Production environment running multiple containers
		- #MTU-1500: multiple transmission size of a layer 3 packet (internet)
			- MTU on local network = 9000
			- MTU on loopback devices = 65535
			- https://www.techtarget.com/searchnetworking/definition/maximum-transmission-unit ([[MTU]])


>[!neurons]
>
[[SMB]] 
[[VPN]]
[[CIDR]]
  