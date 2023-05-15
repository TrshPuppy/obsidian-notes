
# Open System Interconnection Model

A layered networking framework developed by the International Standards Organization ( #ISO) to conceptualize how communication and networking should be done between devices/ entities/ heterogeneous systems.

## ==Advantages:==
- Allows devices w/ different functions and designs to communicate on one network b/c they all conform to OSI.

## 7 Layers:
| 1. Physical Layer  | 2. Data Link Layer | 3. Network Layer | 4. Transport Layer | 5. Session Layer | 6. Presentation Layer | 7. Application Layer |
|-|-|-|-|-|-|-|
| The physical-layer uses a physical medium to transmit individual bits from one node to another | The [data-link-layer](/networking/OSI/data-link-layer.md) Transfers data frames from one node to another connected by a physical layer/ medium | The [network-layer](/networking/OSI/network-layer.md) delivers individual packets of data from one source to another using addressing and routing (non-physical) | The #transport-layer is responsible for delivering the entire message from a source to the destination host | The #session-layer establishes ongoing sessions b/w two users and handles #synchronization, #dialog-control, and other services | The #presentation-layer monitors syntax/ semantics of transmitted data including translation, #compression, and #encryption | The #application-layer provides application program interface API to the user

### Application Layer (7):
Where protocols and rules are in place to determine ==how the user can interact with the data== sent or received.
- Most applications provide a #GUI (Graphical User Interface)
- Includes other protocols like #DNS which converts website addresses into IP addresses

### Presentation Layer (6):
==Translates data== to and from layer 7.
- where standardization starts to take place (data needs to be handled the same way no matter the software/application)
- security features like data #encryption take place here

### Session Layer (5):
Once data is appropriately formatted (L6), the session layer ==begins to create a connection to the device the data is destined for==
- once connection is established a #session is created
- sessions ==are unique==
	- data cannot travel over different sessions

### Transport Layer (4):
When data is sent between devices, it follows one of two protocols:
- [TCP](/networking/protocols/TCP.md) Transmission Control Protocol
- [UDP](/networking/protocols/UDP.md) User Datagram Protocol

### [Network Layer (3)](/networking/OSI/network-layer.md):
Where ==routing and reassembly== take place
- deals with #packets
	- efficient way to transfer data across networked devices
		- exchanged in small pieces ==less bottle-necking==
- #routing = the most optimal path that data should take to a device
	- shortest = has the least amount of devices along path
	- reliable = have packets been lost on this path before?
	- fastest physical connection = is one path using copper (slow) vs fiber?
- Protocols:
	- [OSPF](/networking/protocols/OSPF.md) Open Shortest Path First
	- [RIP](/networking/protocols/RIP.md) Routing Information Protocol
- Addressing via [IP-addresses](/networking/OSI/IP-addresses.md)

### [Data-Link Layer / (L2):](/networking/OSI/data-link-layer.md)
Focuses on ==physical addressing== or transmission.
- receives IP address of destination computer (in packet) and adds [MAC-addresses](/networking/OSI/MAC-addresses.md) 
- deals with #frames
- every network-enabled device has a #NIC / #network-interface-card 
	- comes w/ unique #MAC address

### Physical layer (1):
references the physical components/ medium making up a network which propagates electrical signals which represent data being sent b/w devices.

# Encapsulation:
#Encapsulation: At each layer, pieces of information are added to the data.
- L5  synchronizes the two computers to make sure they are both on the same page ==before== data is sent or received.
- Once checks are finished, data is divided into smaller chunks called #packets 
	- packets sent one at a time
	- when connection is lost ==only the packets that weren't sent== have to be re-sent instead of the entire piece of data.

>[!neurons]
>[[networking]]



