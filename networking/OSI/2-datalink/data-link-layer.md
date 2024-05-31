
# Data Link Layer (L2) (DLL)
Considered the most complex layer of the OSI (abstracts the interaction w/ the hardware from other layers)
- communication b/w end devices and *network interface cards* (NICs)
- Divides packets from the [network-layer](/networking/OSI/3-network/network-layer.md) into frames
- Ensures the *error-free* transmission of data.
- encode, decode,  and organize incoming and outgoing data (between layers 3 and 1) 
## Functions
In the header of each frame, the DLL encapsulates the *source* and *destination* addresses
- Sends ea frame (bit by bit) to the physical layer
	- When the DLL receives bits form the physical layer it organizes them into a frame and sends them to the network layer.
- helps differentiate ea frame from the last (for physical layer)
1. physical addressing
	- the DLL encapsulates the source and destination [MAC addresses](../../../PNPT/PEH/networking/MAC-addresses.md) in the header of ea frame to ensure delivery.
	- A FRAME is the encapsulation of the header and trailer information of a packet
		- header includes source and destination MAC addresses
2. error control
	- If data becomes corrupted (d/t noise, attenuation, etc) the DLL detects the error and corrects it using error detection and correction
	- Adds error-detection bits in the frame's header so the receiver can check for errors in the received data.
	- ex: corrupted data
3. Flow Control
	- If there is a mismatch in speed between the receiving speed and the sending speed then a [buffer overflow](../../../cybersecurity/TTPs/exploitation/binary-exploitation/buffer-overflow.md) can occur, causing frames to be lost
	- the DLL synchronizes the speed between the sender and receiver to establish flow-control between them.
		- Flow control controls the amount of data which can be sent before receiving an acknowledgement from the receiving node
4. access control
## Sublayers
The Data link layer is divided into 2 sublayers, the [Logical Link Control layer](LLC-layer.md) (LLC), and the [Media Access Control layer](MAC-layer.md) (MAC). Layer 2 is split into these sublayers because *it is the most complex layer of the [OSI-reference-model](../OSI-reference-model.md)*.  Both layers have different functions:
### LLC Sublayer
This layer is responsible for [multiplexing](multiplexing.md) the data flowing between layer 2 and [layer 3](../3-network/network-layer.md). It also does error checking, flow control, and synchronization. Regarding addressing, when it receives a *packet* from the network layer, it *divides it into frames* (de-encapsulation) and adds bits to the frame's header which have information information r/t *error coding* and *addressing*.
### MAC Sublayer
The MAC sublayer abstracts physical link control from higher layers so that the complexities of this process are 'invisible' to them. This makes it so that *any LLC sublayer and higher layers can be used with any MAC*.

Responsible for multiplexing and flow control between layer 2 and the physical layer. It also does addressing of *destination stations* (applies a destination address to the data multiplexed from the physical layer).

As for source frames (to be multiplexed to the physical medium), the MAC sublayer encapsulates these frames with into frames appropriate for the physical medium.
### Addressing
Once the data has been de-encapsulated into a frame, some bits are attached to it. 

> [!Resources]
> - [Geeks for Geeks: DLL](https://www.geeksforgeeks.org/data-link-layer/)
> - [Geeks for Geeks: LLC](https://www.geeksforgeeks.org/logical-link-control-llc-protocol-data-unit/)
> - [Neso Academy: Link Layer Services (video)](https://www.youtube.com/watch?v=VBAuzvVzOQU&list=PLBlnK6fEyqRhstjOChz8zuHiFoKGPMr9v&ab_channel=NesoAcademy)
> - [Wikipedia: MAC](https://en.wikipedia.org/wiki/Medium_access_control)
> - [Wikipedia: LLC](https://en.wikipedia.org/wiki/Logical_link_control)





