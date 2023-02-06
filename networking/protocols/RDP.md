---
aliases: [RPD, remote-desktop, remote-desktop-protocol]
---
# Remote Desktop Protocol
Popular protocol which allows remote access to ==Windows== machines.
- Allows users to control their remote Windows machines
- Brings up a GUI desktop w/ access to mouse/keyboard, etc.
- ![[Pasted image 20230205115203.png]]
-CyberArk.com
- communication b/w the client and server is #encrypted w/ #RC4-block-cypher (as default) 
- communication us *asymetric*:
	- most of the data goes from the server to the client
	- ![[Pasted image 20230205115430.png]]
	-CyberArk.com

## Protocol Stack:
![[Pasted image 20230205115520.png]]
-CyberArk.com

Sending/ receiving data through RDP is akin to the #OSI-model. The transmitted data is sectioned, sent to a channel, encrypted, wrapped, framed, and packaged before being sent. Then goes through the same process in reverse once received.
- ==RDP abstracts away the protocol complexity== allowing developers/etc to easily use it and write extensions to it.
- Parts:
	- #TPKT:
		- known as the "ISO Transport Service" on top of [[TCP]]
		- enables peers to exchange information
			- in units known as Transport Protocol Data Units ( #TPDU OR #PDU)
	- #X/224 / X.244:
		- a Connection-Oriented Transport Protocol 
		- provides a connection-mode transport service
		- used by RDP in the ==initiial connection request and response==
	- T.125 MCS/ #T/125-MCS:
		- Multi-point Communication Service
		- allows RDP to communicate through *multiple channels*

## Connection:
1. Connection Initiation
	- connection initiated by the client w/ an #X/224 connection  request PDU
2. Basic Settings Exchange
	- basic settings exchanged b/w the client and the server like RDP version, desktop resolution, keyboard info, hostname, etc.
	- also includes security data (encryption methods, server certificate, etc) and network data ( #channels)
3. Channel Connection
	- the stage where every individual channel connection is made.
	- sub-stages:
		- MCS Erect Domain Req.:
		- MCS Attach User Req.:
		- MCS Attach User Confirm:
		- MCS Channel Join Request and Conf.:
4. Security Commencement
	- client sends #security-exchange-PDU which contains the client random encrypted w/ the server's #public-key
	- client and server use the random numbers to create session encryption keys.
	- now ==subequent traffic can be encrypted== 
5. Secure Settings Exchange
	- client sends encrypted #client-info-PDU w/ info about compression, user domain, username, password, etc.
6. Licensing
	- Not always configured:
		- in order to support 2 simultaneous connections, a licence must have been purchased from Microsoft.
		- If there is no licensing, servers sends a PDU to the client which approves its license (for 2 sessions only)
7. Capabilities Exchange
	- server sends its capabilities in a #Demand-Active-PDU
		- This includes input(keyboard type/features), fonts, etc.
	- client responds w/ a #Confirm-Active-PDU which includes its own set of capabilities
8. Connection Finalization
	- client and server exchange some PDUs to finalize the connection, all originating from the client.
	- PDUs:
		- #Client/Server-synchronize-PDU - used to synchronize identifiers b/w the client and server
		- #Client/Server-control-PDU - both send this PDU to indicate shared control of the session.
		- #Client-control-PDU - client sends the request to control and the server grants it
		- #Persistent-key-list-PDU - client sends a list of keys, ea key identifies a cached bitmap.
			- allows bitmap to be persistent (instead of ending when connection ends)
			- #bitmap-caching: method to reduce network traffic needed to transfer a GUI from the server to the client
		- #Font-list/map-PDU - deprecated? used to be used to hold info about fonts
9. Data Exchange 
	- once connection is finalized, bulk of the data is sent from server to client (input and graphical data)

## Security:
Standard vs Enhanced:
- Standard security:
	- traffic encrypted w/ RSAs RCP algorithm.
		- uses client and server random values exchanged during the Basic Settings Exchange phase.
- Enhanced:
	- allows RDP to outsource security operations (encryption/decryption, integrity checks, etc) to an external #security-protocol
	- Protocols:
		- #TLS 1.0/1.1/1.2
		- #CredSSP
			- Network Level Authentication( #NLA): CredSSP uses this to authenticate the user BEFORE initializing the RDP connection 
		- #RDSTLS

### Recent exploits:
- [[BlueKeep]] (CVE-2019-0708)/ #BlueKeep:
- [[DejaBlue]] (CVE-2019-1181 & CVE-2019-1182)/ #DejaBlue



>[!links]
>https://www.cyberark.com/resources/threat-research-blog/explain-like-i-m-5-remote-desktop-protocol-rdp

>[!related]
>[[xfreerdp]]
> #port-3389 

