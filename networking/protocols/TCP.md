
# Transmission Control Protocol
Protocol for sending data between devices which guarantees reliability.
## Advantages:
- Guarantees accuracy of data
- Able to synchronize two devices to prevent either being flooded w/ information
- reliable
- Error checking:
	- ex: if packets sent from the [session-layer](../OSI/5-session/session-layer.md) are not received and sent in the same order, transport layer catches this.
## Disadvantages:
- requires a reliable connection b/w devices
	- If one packet gets dropped, the entire chunk of data cannot be used
- slow connection can bottleneck another device
	- connection is reserved for receiving computer
- slower than [UDP](UDP.md) 
- devices have to do more work for TCP

![](/networking/networking-pics/TCP-1.png)
-TryHackMe.com
## Reliability:
TCP reserves a constant connection between two devices for as long as it takes for data to be fully sent and received.
#### 3 Way handshake:
Sets up connection b/w two machines:
- ex: Bob calls Alice, the call connects but someone has to say  "hello?" to know they've successfully connected.
- *SYN flag*: initial packet sent by the sending device/ client at start of handshake
	- used to start connection and synchronize devices
	- client: "Here is my *Initial Synchronization Number* (ISN) to synchronize with (0) "
- *SYN/ACK flag*: sent by target machine once it receives SYN
	- (acknowledges the synchronization attempt by the client)
	- server: "I *acknowledge* your ISN is (0), my ISN is (5000)"
- *ACK flag*: acknowledgement used by either party to confirm that a series of messages/ packets have successfully been transmitted.
	- client: I *acknowledge* your ISN is (5000), here is my first data which is my ISN+1 (5000+1)
- *DATA flag:* once connection is established, data is sent w/ this flag attached
- *FIN flag:* used to cleanly close a connection after it is completed
	- Once the receiving device has received all of the data
		- *close TCP connections as soon as possible* b/c they use a lot of resources
	- To initiate closing a connection:
		- one device will send the "FIN" packet to the other device
		- Other device has to acknowledge the FIN
		- ![](/networking/networking-pics/TCP-2.png)
		- -TryHackMe.com
- *RST flag:* abruptly ends all communication
	- indicates there was a problem during the process (like service not working properly or has low resources)
## TCP Packets:
Contain headers added by *encapsulation*
### Headers:
#### Source port: the port opened by the sender
Chosen randomly (out of the 0-65k+ ports which aren't already in use)
#### Destination port
the port the application/ service is running on on the destination host. Not chosen at random like the source
#### Source IP
IP of the sending device
#### Destination IP
IP of the receiving device
#### Sequence number
When connection occurs. First piece of info transmitted is a random number
#### Acknowledgment number
Once data has been given sequence number:
- the number for next piece of data will be sequence number++
#### Checksum
gives TCP *TEGRITY*
- math calculation is made w/ output remembered.
- when receiving device performs the calculation, *the data is corrupt if the answer is not the same*
#### Data header
where the data is stored in bytes
#### Flag header
determines how the packet should be handled by either device during the handshake
- specific flags = specific behaviors

>[!Related]
> - RFC-793 

