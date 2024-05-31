
# Network Layer (L3)
Provides services to allow end devices to exchange data.
## Major Functions:
1. Addressing end-devices
2. #Encapsulation
3. Routing
4. De-encapsulation
## Packets:
How data is referred to and encapsulated in the #network-layer:
#### Packet structure:
- structure differs r/t the type of packet being sent.
	- ex: A packet using #IP protocol will have headers that contain additional information to the data being sent across the network
	- ex of different #headers:
		- Time to live: expiration of the packet
		- Checksum: integrity checking for protocols like #TCP/IP 
			- if any data is changed in this header the packet will be considered corrupted
		- Source Address: IP address of the source machine
		- Destination Address: IP of the dest machine