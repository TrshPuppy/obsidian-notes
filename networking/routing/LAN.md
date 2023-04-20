
# Local Area Network / #LAN 

## Types of Devices:
#### Switches:
a #switch is a dedicated device in a network designed to aggregate other devices including computers, printers etc.
- Ea device plugs into the switch's port
- keep track of which device is connected to which port:
	- More efficient than #hubs or #repeaters 
	- when they receive a packet, they send it to the right device
		- reduces network traffic
		- repeaters and hubs: repeat the packet to every port
- Switches can be connected to routers which ==increases network redundancy==
- Can operate on [data-link-layer](/networking/OSI/data-link-layer.md) OR L3 but cannot do both (the switch has to be one or the other)

Below: This L2 switch can only forward #in-memory-database frames to the connected devices using their #MAC-addresses 
![[Pasted image 20230212104825.png]]
-TryHackMe.com

- Layer 3 switches:
	- ==can do some of the things a router can do==
		- will send frames to connected L2 devices, and will use #IP protocol to route packets to L3 devices
Below: This L3 switch can route packets to the two connected #VLANs (Virtual Local Area Networks)
![[Pasted image 20230212105329.png]] 
-TryHackMe.com

#### Routers:
a #router connects networks so data can be passed between them.
- uses #routing 
	- data traveling across networks
	- data is given a label as it travels
	- path taken is decided base on:
		- what path is shortest?
		- what path is most reliable?
		- what has the fastest physical medium?
- routers = [network-layer](/networking/OSI/network-layer.md) (L3)
	- usually have a GUI which allows for configuring #port-forwarding. #firewalls, etc.

## Topologies:
1. Star Topology/ #star-topology:
	- devices individually connected to a central networking device like a #hub or #switch
	- most common
	- Any info sent to a device in this topology is sent via the central device
	- ==Advantages:==
		1. more scalable (adding more devices is easy)
	- ==Disadvantages:==
		1. as the network grows --> more maintenance
		2. if central device fails: connected devices not able to send/ receive data
		3. expensive
![[Pasted image 20230206210338.png]]
-Hack the Box
2. Bus Topology/ #bus-topology
	- A single common connection known as a " #backbone-cable"
	- Devices stem off a main branch like leaves
	- ==Disadvantages:==
		- All data traveling along main branch = SLOW
		- difficult to troubleshoot issues
		- no redundancy in case of failure
	- ==Advantages:==
		- easy to set up
		- cost effective
![[Pasted image 20230208184256.png]]
3. Ring Topology/ #ring-topology:
	- also called "token-topology"
	- Data is sent around the loop TO EA COMPUTER until it reaches the one it was addressed for
		- If a device has its own data to send, it will send its own first, then the transferring data
	- ==Advantages:==
		- easy to troubleshoot issues
		- less prone to bottlenecking
	- ==Disadvantages==
		- a fault along the cable will cause entire network to crash
		- not efficient way of sending data
