---
aliases: [MTU, maximum-transmission-unit]
---
>[!links]
>https://www.techtarget.com/searchnetworking/definition/maximum-transmission-unit

# Maximum Transmission Unit
The largest size #frame or #packet (in bytes) which can be transmitted acriss a data-link
	Most often used in reference to packet size across an Ethernet connection using #IP (internet protocol)

### #packet-fragmentation:
ea device in a network has an MTU size it can receive and transmit.
	- The MTU of the next receiving device is determined before the packet is sent
		- if the packet is too large, the receiving device cannot accept it so the packet is divided into fragments and sent
		- this is called #packet-fragmentation 
	- fragmentation is bad for performance and adds delay and extra data
	- #IPV4 allows for #packet-fragmentation unless the #do-not-fragment-flag is set
	- #IPV6 does *NOT* allow fragmentaion
		- if a packet size exceeds its #MTU it will be dropped