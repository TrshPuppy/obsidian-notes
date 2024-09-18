
# Internet Protocol Security (IPsec)
Init.
IPsec is a network encryption protocol *suite* which provides security for IP communication. Each [network layer](../OSI/3-network/network-layer.md) packet is encrypted within a session of communication. This not only obfuscates the data, but also *provides authentication*. IPsec also uses *packet signing.*

The data sent over layer 3 is encrypted, which sort of creates *tunneled connection.* IPsec is *widely used and standardized*, which makes it easy to implement between different peers.
## Protocols Used
### [Authentication Header](AH.md) (AH)
Provides integrity via hashes and a secret *shared key* used in the algorithm.
### [Encapsulating Security Protocol](ESP.md) (ESP)
Provides authentication *and encryption* of packets in IPsec. Provides 'encryption-only' and 'authentication-only' modes but *both should be enabled*.

> [!Resources]
> - [Professor Messer](https://www.youtube.com/watch?v=yuXK_Jyosus&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=101)

