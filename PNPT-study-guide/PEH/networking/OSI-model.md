
# [OSI Reference Model](/networking/OSI/OSI-reference-model.md)
A representation of networking used to contextualize the different protocols and layers of encapsulation that data has to travel thru to go from one device to another across a network.

## Pneumonic:
###### Please
###### Do
###### Not
###### Throw
###### Sausage
###### Pizza
###### Away

### L1: Physical (please)
Handles the transmission of electrical signals along physical mediums. Relates to data cables like ethernet/CAT-5, etc..
### L2: [Data-link](/networking/OSI/data-link-layer.md) (do)
Handles [multiplexing and de-multiplexing](/networking/OSI/multiplexing.md) of electrical messages from layer 1. This is the most complex layer because it abstracts away the work of converting electrical signals into meaningful data. It's also split into 2 sublayers, the *Logical Link Control* and *Medium Access Control* layers.

Uses [MAC Addresses](/networking/OSI/MAC-addresses.md) to identify devices, as well as switches to route traffic between them. Data in this layer is encapsulated to and from *frames*.
### L3: [Network](/networking/OSI/network-layer) (not)
The network layer is in charge of transmitting data (encapsulated into packets) from devices using [IP Addresses](/networking/OSI/IP-addresses.md) for addressing, and L3 devices like routers for routing.
### L4: [Transport](/networking/OSI/OSI-reference-model.md#transport-layer-4) (throw)
Handles communication across a network using the [TCP](/networking/protocols/TCP.md) and [UDP](/networking/protocols/UDP.md) protocols. 
### L5: [Session](/networking/OSI//networking/OSI/OSI-reference-model.md#session-layer-5) (sausage)
In charge of creating and maintaining a connection between two parties sending and receiving data b/w each other. Once connection is established, the session is created. Each session is unique to its connections, meaning data should not be able to travel over different sessions.
### L6: [Presentation](/networking/OSI/OSI-reference-model.md#presentation-layer-6) (pizza)
This is the layer where standardization of how data can be transmitted starts to apply. Also includes security features like encryption.
### L7: [Application](/networking/OSI/OSI-reference-model.md#application-layer-7) (away)
Has protocols which dictate how a user can interact with the data being sent or received. This usually involves a Graphical User Interface (GUI), and also includes protocols like [DNS](/networking/DNS/DNS.md) to help render an internet resource like a webpage on a web browser.

> [!My previous notes (linked in text)]
> - [OSI model](https://github.com/TrshPuppy/obsidian-notes/blob/main/networking/OSI/OSI-reference-model.md)
> - [Data-Link Layer](https://github.com/TrshPuppy/obsidian-notes/blob/main/networking/OSI/data-link-layer.md)
> - [Multiplexing](https://github.com/TrshPuppy/obsidian-notes/blob/main/networking/OSI/multiplexing.md)
> - [IP Addresses](https://github.com/TrshPuppy/obsidian-notes/blob/main/networking/OSI/IP-addresses.md)
> - [MAC Addresses](https://github.com/TrshPuppy/obsidian-notes/blob/main/networking/OSI/MAC-addresses.md)
> - [Network Layer](https://github.com/TrshPuppy/obsidian-notes/blob/main/networking/OSI/network-layer.md)
> - [TCP](https://github.com/TrshPuppy/obsidian-notes/blob/main/networking/protocols/TCP.md)
> - [UDP](https://github.com/TrshPuppy/obsidian-notes/blob/main/networking/protocols/UDP.md)
> - [DNS](https://github.com/TrshPuppy/obsidian-notes/blob/main/networking/DNS/DNS.md)


