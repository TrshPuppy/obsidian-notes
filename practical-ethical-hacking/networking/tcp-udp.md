
# TCP, UDP, and the Three Way Handshake

## TCP vs. UDP
TCP (Transmission Control Protocol) and UDP (User Datagram Protocol) are relevant to Layer 4 of the OSI model. TCP is focused on establishing a reliable connection between parties using the Three Way Handshake, while UDP focuses on sending data between parties w/o ensuring a reliable connection between them first.

### Three Way Handshake
The three way handshake is used in TCP to set up a reliable connection between parties. To begin a TCP connection three flags must be sent in this order:

#### SYN
Requesting party sends a `SYN` flag, which is the initial packet and starts the process of the handshake. Consists of an Initial Synchronization Number (ISN) for the other party to synchronize with (ex: ISN = 0)

#### SYN ACK
When the receiving party receives the `SYN` flag, it responds with a `SYN ACK` flag. This flag basically tells the first device "I have received your ISN of 0. My ISN is 5000 (for example)."

#### ACK
When the original device receives the `SYN ACK` flag from the target machine, the first machine sends an `ACK` flag to *acknowledge* that it has received a series of packets from the target device.

It says "I acknowledge your ISN of 5000, here is the my first message containing data to you, which is my ISN+1 (5001)"

#### DATA
Once connection has been established via the SYN/ACK three way handshake, subsequent messages from the source device will have the `DATA` flag until it has finished sending all of its data.

> [!Resources]
> My own previous notes:
> > Local path:
> > > Links to other notes local to my obsidian notes directory will work if you've downloaded the entire thing, but not on GitHub.
> > 
> > GitHub:
> > > [TCP](https://github.com/TrshPuppy/obsidian-notes/tree/main/networking/protocols/TCP.md)
> > > [UDP](https://github.com/TrshPuppy/obsidian-notes/tree/main/networking/protocols/UDP.md)
