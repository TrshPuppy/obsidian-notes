
# Link-Local Multicasting Name Resolution
A [DNS](DNS.md) protocol which allows hosts to resolve hostnames on the same local link (allows name resolution w/o a DNS server).
## Mechanism:
LLMNR is able to resolve a host name to an [IP address](networking/OSI/IP-addresses.md) by sending a *multicast-packet* across the network to all listening interfaces. The packet asks each interface if they are the authoritative hostname.
- uses [UDP](/networking/protocols/UDP.md) `port 5355`

> [!Resources]
> - [Hacking Articles: Detailed Guide to Responder](https://www.hackingarticles.in/a-detailed-guide-on-responder-llmnr-poisoning/)

> [!Related]
> TTPs: [LLMNR Poisoning](cybersecurity/TTPs/exploitation/LLMNR-poisoning.md)