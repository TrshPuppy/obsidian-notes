
# Multicast DNS
A protocol which helps with name resolution w/i a network.

## Mechanism:
Instead of querying a name server, it multicasts queries to all clients on the network. 

### Multicasting:
In #multicasting an individual message is aimed at a group of recipients. When a successful connection is made, all participants in the group are informed of the connection and the resolved [IP address](IP-addresses.md) so a corresponding entry can be made in their #mDNS-cache.

>[!Links]
>[Hacking Articles: Detailed Guide to Responder](https://www.hackingarticles.in/a-detailed-guide-on-responder-llmnr-poisoning/)

