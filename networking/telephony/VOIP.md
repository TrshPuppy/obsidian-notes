# Voice Over Internet Protocol
Uses a standard broadband internet connection. 
## Softphone
Software which allows a device to work as a phone.
## SIP - Session Initiation Protocol
SIP maps phone numbers to IP addresses, similar to how [DNS](../DNS/DNS.md) works. VOIP uses SIP to *initialize* a call. When you dial a number, SIP is used to find the IP address matching that phone number.
## RTP - Real-time Transfer Protocol
RTP is used to *encapsulate* the digital signal of a call (after the analog data has been converted to digital data by the ADC) into small data packets to be transferred over a network. It can be used for both audio and video data.
Once the packets arrive at the recipient, they're re-assembled so they can be understood by the recipient.

> [!Resources]
> - [Asterisk setup](https://www.youtube.com/watch?v=DZ0czppbamo)

