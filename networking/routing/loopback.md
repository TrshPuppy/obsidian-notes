
# Loopback IP Addresses
The loopback #CIDR-block, *127.0.0.0/8* is a reserved collection of addresses.
- It mocks the #TCP/IP server or TCP/IP client on the same system.
- ex: 127.0.0.1 is the commonly used address for a machine and is a network address which can be used to refer to the current machine you're on
	- ex: if you're on your desktop, 127.0.0.1 refers to your desktop

Steve:
- computer OS ships w/ a #TCP-IP-stack which understands [TCP](/networking/protocols/TCP.md) 
	- when anything in computer wants to access a network resource via TCP/IP it goes through the IP stack
	- computer also has a #network-card / interface (ex: ethernet/wifi)
		- knows how to physically connect to the network
		- "network interface" (represents network card) has an IP address (usually given to it by the router)
			- ex: 192.168.0.5/24
			- Also knows its own MAC address (of the physical card)
				- ex: 00:00:00"00:00:01
			- [VPN](/networking/routing/VPN.md): *creates a virtual network interface (w/ virtual IP and #MAC-addresses )
				- ex 10.0.0.12/8
				- default route: 10.0.0.1
	- computer knows routes:
		- #subnet-mask
		- #routing-table
			- Network: 192.168.0/24
				- Interface: 192.168.0.5 (how it can route to that IP)
			- Network: 10/8
				- Interface: 10.0.0.12
			- default route (for #network-card ) is 192.168.0.1
- In the web browser:
	- ex: want to access Google.com
		- First: [DNS](/networking/DNS/DNS.md) servers (same IP as the router)
			- IP: 192.168.0.1
			- Browser asks IP stack in OS for IP address which corresponds to Google.com
				- needs to find the DNS server
					- looks at  routing table
						-  the DNS is 192.168.0.1
			- [ARP](/networking/protocols/ARP.md) request sent:
				- "who on this network has the IP 192.168.0.1" (layer 2)
					- goes to router
					- router has IP address cached so responds wwith:
						- ":03 is the MAC of the IP 192.168.0.1"
				- #ARP-table :
					- new entry made: 
						- IP: 192.168.0.1
						- MAC: 00:00:00:00:00:00:03
			- [DNS](/networking/DNS/DNS.md) request sent:
				- request to 192.168.0.1 via :03
					- packet has header for IP address (L3) then MAC (L2)
			- DNS responds:
				- IP is 8.8.8.8 (for google.com as example)
		- Web browser says it wants to send packets to 8.8.8.8
			- 8.8.8.8 does not exist in the routing table yet
				- but there are default routes in the table
				- since we don't have 8.8.8.8 we send it to the default route (192.168.0.1)
				- Browser send packet w/:
					- dest IP: 8.8.8.8
					- source IP: 192.168.0.5
		- Router picks up packet from browser:
			-  receives packet w/ dst of 8.8.8.8 src: 192.168.0.5
			- routers can do #network-address-translation 
				- "pretends" to send the packet
					- has its own routing table and IP stack 
					- If public IP (of router) is 5.5.5.5
					- If the routing table does not have a route to 8.8.8.8
						- sends a packet w/ dst IP o f8.8.8.8 and src of 5.5.5.5 ( #network-address-translation )
							- cannot use the 192.168.0.5 address b/c it is a private IP
						- packet will be sent from Router to next router in ISP (hop) and will hop until it finds a router who knows how to get to 8.8.8.8
						- once a router knows the answer, it will send the info back to the original router
							- route can then be saved in the routers routing table
			- router has a public IP (from ISP) and its own IP w/i your network
- #Localhost:
	- The web server can talk to the computers IP stack
		- listens to HTTP request etc.
	- web browser wants to talk to 127.0.0.1
		- browser doesn't know
		- asks the IP stack
			- no DNS request because it already has the IP (DNS connects names to IPs)
			- browser sends HTTP request w/ GET to IP stack
				- looking for dst IP of 127.0.0.1
				- also has TCP header
				- Dst port of 80 (part of TCP)
			- TCP/IP stack KNOWs that 127.0.0.1 is a special case
				- Says: "This is me, Im gonna loop it back to myself"
					- W/i the IP stack it asks if anyoone is listening on TCP port 80?
						- web server is listening on port 80
				- No packets or any interfaces on the actual network were involved 

![](/networking/networking-pics/IP-routing-steve.png)

![](/networking/networking-pics/IP-routing-steve-2.png)

>[!links]
>https://www.geeksforgeeks.org/what-is-a-loopback-address/
