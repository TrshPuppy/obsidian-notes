
# Ethernet Switching
#ethernet operates in #L1 / #physical-layer and #L2 / [data-link-layer](/networking/data-link-layer.md) 
 
## Ethernet Frames:
Ea frame is a minimum of 64 bytes and maximum of 1518 bytes.
- Any frame < 64 bytes is called a #collision-fragment or #runt-frame and is automatically discarded.
	- Frames which are > 1518 bytes are called #jumbo-frames or #baby-giant-frames and are also discarded
- Fields:

|8 bytes|6 bytes|6 bytes|2 bytes|45-1500 bytes|4 bytes|
|-|-|-|-|-|-|
| #preamble and #SFD | Dest MAC address | Src MAC address | Type/length | data | #FCS |

### Ethernet Encapsulation:
- a family of networking technologies developed and defined by the #IEEE-802/2 and #IEEE-802/3 standards
	- IEEE 802.2 deals w/ the #LLC-sublayer 
		- places information in the frame to identify which [network-layer](/networking/OSI/network-layer.md) protocol is used for the #frame
	- IEEE 802.3 deals w/ the #MAC-sublayer 
		- responsible for data #encapsulation and #media-access-control
		- provides Data Link Layer addressing
	- * 802.3 is various ethernet standards, #IEEE-802/11 is #WLAN standards for #wireless communication, and #IEEE-802/15 is #WPAN standards ( #bluetooth, #RFID)
- IEEE 802.3 data encapsulation includes:
	- #ethernet-frame: the internal structure of the Ethernet frame
	- #ethernet-addressing: the Ethernet frame includes both the #source and #destination #MAC-addresses  to deliver the frame (from the #network-interface-card /NIC to the receiving NIC on the same #LAN)
	- #ethernet-error-detection:
		- the frame includes a #frame-check-sequence (FCS) trailer which is used for error detection

### Media Access:
- 802.3 has specifications for ethernet communication standards over different media (ex: copper, fiber) 
	- ex: #IEEE-802/3u, #IEEE-802/3z, #IEEE-802/3ab, #IEEE-802/3ae, etc.
- When sending data across a shared media, there needs to be a way to detect #collisions 
	- #legacy-ethernet used a "bus topology" (point to point)
		- #hubs
		- #half-duplex: can only send OR receive (not both at the same time)
		- #collision-detection: #CSMA/CD Carrier Sense Multiple Access/ Collision Detection
			- allows for detection on the medium
			- collision = #hold-down-timer placed so transmission is paused to be tried again later
	- today's ethernet:
		- #full-duplex
		- [switches](/networking/routing/switches.md)
		- All gigabit connections are full duplex
		- collision detection: doesn't require CSMA/CD because ea #collision-domain is tied to each port and not to the entire device

>[!links]
> [Arthur Salmon: YouTube](https://www.youtube.com/watch?v=q4ZGh7lNQgw&ab_channel=ArthurSalmon)

