
# User Datagram Protocol
#UDP is a protocol used for transferring data between devices which guarantees speed of transfer.
![[Pasted image 20230208201648.png]]
(if only packets 1 and 3 make it to the destination) -TryHackMe.com

### ==Unlike TCP:==
- no error checking
- not reliable
- no synchronization
- ==connection is stateless==

## ==Advantages:==
- much faster than #TCP 
- leaves control of how quickly packets are sent up to the #session-layer 
- does not reserve a continuous connection between devices

## ==Disadvantages:==
- Doesn't care if data is received
- unstable connection = terrible user experience

## UDP Packets:
![[Pasted image 20230208211514.png]]
### Types of Headers:
1. #TTL / Time to Live: packet expiration time
2. #source-address: IP of sending device
3. #Destination-address: IP of receiving device
4. #source-port : the port opened by the receiving device to receive the data
	- chosen randomly from 0-65k+ of available ports
5. #destination-port : the port where the receive device decides to receive the data
6. #data-header : the data