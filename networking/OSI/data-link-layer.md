
# Data Link Layer (L2) (DLL)

Considered the most complex layer of the OSI (abstracts the interaction w/ the hardware from other layers)
- communication b/w end devices and #network-interface cards
- Divides packets from the [network-layer](/networking/OSI/network-layer.md) into frames
- Ensures the *error-free* transmission of data.
- #encode, #decode and organize incoming and outgoing data.

## Major Functions:
1. #framing: 
	- receives a #packet from the #network-layer (referred to as a #frame in the DLL)
	- Divides the received #packets into #frames 
	- Attaches some bits for error coding and #addressing to the headers and ends of the frames
	- Sends ea frame (bit by bit) to the #physical-layer 
		- When the DLL receives bits form the #physical-layer it organizes them into a #frame and sends them to the network layer.
	- helps differentiate ea frame from the last (for physical layer)
2. #addressing (physical)
	- the DLL encapsulates the #source and #destination #MAC-addresses in the header of ea frame to ensure delivery.
	- A FRAME is the encapsulation of the header and trailer information of a packet
		- header includes source and destination MAC addresses
3. #error-control:
	- If data becomes corrupted (d/t noise, attenuation, etc) the DLL detects the error and corrects it using #error-detection and #error-correction
	- Adds error-detection bits in the frame's header so the receiver can check for errors in the received data.
	- ex: corrupted data
4. #flow-control:
	- If there is a mismatch in speed between the #receiving-speed and the #sending-speed then a #buffer-overflow can occur, causing frames to be lost
	- the DLL synchronizes the speed between the sender and receiver to establish flow-control between them.
		- Flow control controls the amount of data which can be sent before receiving an acknowledgement from the receiving node
5. #access-control
	- (media access control)

## *Has 2 sub-layers:*
1. "Logical Link Control" ( #LLC-sublayer)
	- the #LLC acts as an interface between the MAC-sublayer and the #network-layer (OSI layer 3)
	- error messages and acknowledgement
2. "Medium Access Control" ( #MAC)
	- the sub-layer responsible for controlling the hardware which interacts w/ wired or #optical-wireless transmission medium.
	- addressing #frames 
	- control access to physical media
		- [MAC-addresses](/networking/OSI/MAC-addresses.md) 
- The #LLC-sublayer provides #flow-control and [multiplexing](/networking/OSI/multiplexing.md) for the #logical-link, while the #MAC provides flow control/ multiplexing for the transmission medium

The Data-Link layer has a "flat-topology"
- No layering between devices
	- can only grow horizontally
- As more devices are added to a #switch's table of MAC addresses, the table grows and becomes less efficient
	- (need to expand network in a different way)

>[!links]
>https://www.geeksforgeeks.org/data-link-layer/
>https://www.youtube.com/watch?v=VBAuzvVzOQU&list=PLBlnK6fEyqRhstjOChz8zuHiFoKGPMr9v&ab_channel=NesoAcademy
>
> LLC and MAC sublayers:
> 
> https://en.wikipedia.org/wiki/Medium_access_control
> https://en.wikipedia.org/wiki/Logical_link_control]



