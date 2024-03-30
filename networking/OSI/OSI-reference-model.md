
# Open System Interconnection Model
A layered networking framework developed by the International Standards Organization (ISO) to conceptualize how communication and networking should be done between devices/ entities/ heterogeneous systems.

Allows devices w/ different functions and designs to communicate on one network b/c they all conform to OSI.
## Encapsulation
Encapsulation is an important principle in the OSI model. It describes the process through which pieces of information are added to the data at each layer. 

Each piece of data can be read and understood by only certain protocols of each layer. For example, the IP address of the destination computer can be read off a data packet by layer 3 devices, but not by layer 2 devices.
## 7 Layers
| 1. Physical Layer                                                                              | 2. Data Link Layer                                                                                                                             | 3. Network Layer                                                                                                                                                 | 4. Transport Layer                                                                                         | 5. Session Layer                                                                                                             | 6. Presentation Layer                                                                                                    | 7. Application Layer                                                         |
| ---------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| The physical-layer uses a physical medium to transmit individual bits from one node to another | The [data-link-layer](/networking/OSI/data-link-layer.md) Transfers data frames from one node to another connected by a physical layer/ medium | The [network-layer](/networking/OSI/network-layer.md) delivers individual packets of data from one source to another using addressing and routing (non-physical) | The transport-layer is responsible for delivering the entire message from a source to the destination host | The session-layer establishes ongoing sessions b/w two users and handles synchronization, dialog-control, and other services | The presentation-layer monitors syntax/ semantics of transmitted data including translation, compression, and encryption | The application-layer provides application program interface API to the user |
### Application Layer (7)
Where protocols and rules are in place to determine *how the user can interact with the data* sent or received. Most applications provide a GUI (Graphical User Interface) as this layer. Includes other protocols like [DNS](/networking/DNS/DNS.md) which converts website addresses into [IP](/networking/OSI/IP-addresses.md) addresses.
### Presentation Layer (6)
*Translates data* to and from layer 7. This is where standardization starts to take place (data needs to be handled the same way no matter the software/application) Additionally, security features like data encryption take place here.
### Session Layer (5)
Once data is appropriately formatted (L6), the session layer *begins to create a connection to the device the data is destined for*. Once connection is established a session is created. Sessions *are unique* and data cannot travel over different sessions.
### Transport Layer (4)
When data is sent between devices, it follows one of two protocols:
- [TCP](/networking/protocols/TCP.md) Transmission Control Protocol
- [UDP](/networking/protocols/UDP.md) User Datagram Protocol
### [Network Layer (3)](/networking/OSI/network-layer.md)
Layer 3 is where [routing](networking/routing/routing-table.md) and assembly takes place. This layer handles data as packets. Packets and routing are an efficient way to transfer data across networked devices. This is because the data is fragmented and exchanged as small pieces which causes *less bottle necking.*
#### Routing
Routing protocols b/w layer 3 devices make data exchange efficient. In routing, data is *routed* along the most optimal path to a target device. The principals of routing aim to ensure that packets are sent on routes which are:
- the shortest: has the least amount of devices along path
- reliable: have packets been lost on this path before?
- fastest physical connection: is one path using copper (slow) vs fiber?
##### Routing Protocols:
- [OSPF](/networking/protocols/OSPF.md) Open Shortest Path First
- [RIP](/networking/protocols/RIP.md) Routing Information Protocol
- Addressing via [IP-addresses](/networking/OSI/IP-addresses.md)
### [Data-Link Layer / (L2)](/networking/OSI/data-link-layer.md)
This layer focuses on *physical addressing* or transmission. When a frame of data is received on this layer, the [MAC address](/networking/OSI/MAC-addresses.md) of the destination computer is added to the frame.

Every network-enabled device has a Network Interface Card (NIC) which comes with a unique MAC address.
### Physical layer (1)
This layer references the physical components/ propagates data in the form of electrical signals between devices on a network.
