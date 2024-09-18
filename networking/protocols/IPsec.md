
# Internet Protocol Security (IPsec)
IPsec is a network encryption protocol *suite* which provides security for IP communication. Each [network layer](../OSI/3-network/network-layer.md) packet is encrypted within a session of communication. This not only obfuscates the data, but also *provides authentication*. IPsec also uses *packet signing.*

The data sent over layer 3 is encrypted, which sort of creates *tunneled connection.* IPsec is *widely used and standardized*, which makes it easy to implement between different peers. If your network's [firewall](../../cybersecurity/defense/firewalls.md) uses IPsec, you'll probably be able to use it to communicate w/ another network's firewall *regardless of the vendor* because it IPsec is very standardized.
## IPsec Headers
Most implementations of IPsec will use a *combination of the protocols AH and ESP* to ensure that packets are both encrypted and authenticated.
### AH
**Authentication Header:** This is a header which can be added to an IPsec packet *to provide integrity* (not encryption). AH uses [hashing](../../computers/concepts/cryptography/hashing.md) (via *SHA-2* usually) and a secret *shared key* to provide authentication. The `AH Header` itself is a *hash of the packet and the shared key* (the key is shared b/w concentrators).
![](../networking-pics/Pasted%20image%2020240712112627.png)
The packet can be added to the packet as part of the `IPsec Headers` segment (in these pictures). This provides:
- integrity (via hashing)
- guaranteed origin (authentication w/ shared keys)
- protection against *replay attacks* (by using sequence numbers)
### ESP
**Encapsulating Security Protocol**: this header is able to provide authentication *and encryption* of packets in IPsec. It uses *SHA-2* for hashing and *AES* for encryption. It adds its own `ESP Header` and `ESP Trailer` as well as an `Integrity Check` segment.
![](../networking-pics/Pasted%20image%2020240712113032.png)
The `Integrity Check` Trailer/ segment helps to ensure the data b/w the ESP headers *is encrypted* and the packet makes it through the tunnel okay. ESP Provides 'encryption-only' and 'authentication-only' modes but *both should be enabled*.
## Transport & Tunnel Mode
![](../networking-pics/Pasted%20image%2020240712113746.png)
There are two ways to send encrypted data over a tunnel using IPsec, transport mode and tunnel mode. Both add *additional headers* to the original packet.
### Transport mode
![](../networking-pics/Pasted%20image%2020240712114023.png)
In transport mode the `IP Header` from the original packet is moved to the front of the packet and `IPsec Header`s are added in between it and the data. The data is then *encrypted* and, at the end of the data segment, `IPsec Trailer`s are added. 

In transport mode the `IP Header` is still sent accross the tunnel in clear text, meaning it is not protected.
### Tunnel mode
![](../networking-pics/Pasted%20image%2020240712114103.png)
Tunnel mode is the most common implementation and uses both AH and ESP. In tunnel mode, the `IP Header` is protected. Instead of being moved to the beginning of the packet, the `IP Header` stays where its at and an `IPsec Header` and a `New IP Header` are added in front of it. The `New IP Header` is usually the [IP address](../../PNPT/PEH/networking/IP-addresses.md) of the *receiving concentrator*.

> [!Resources]
> - [Professor Messer](https://www.youtube.com/watch?v=yuXK_Jyosus&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=101)
> - [Professor Messer](https://www.youtube.com/watch?v=YFyt8aY8PfI&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=110)

> [!Related]
> - [LT2P](../design-structure/VPN.md#LT2P)


