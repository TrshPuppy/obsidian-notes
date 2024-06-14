
# Autonomous System Number
An autonomous system is a group of *IP prefixes* which are run by network operators who *maintain the same [routing](/networking/routing/routing-table.md) policy.* Each AS is assigned an *Autonomous System Number* by the IANA. This number is meant to identify a large network which *serves a set of subnets* (with the same IP prefixes).

It's a "connected group of one or more [IP](/networking/OSI/IP-addresses.md)s run by one or more network operators which have a SINGLE and CLEARLY DEFINED routing policy (which dictate how routing decisions are made).
## RFC-1930
```              
NET1 ......  ASX  <--->  ASY  ....... NET2

   ASX knows how to reach a prefix called NET1.  It does not matter
   whether NET1 belongs to ASX or to some other AS which exchanges
   routing information with ASX, either directly or indirectly; we just
   assume that ASX knows how to direct packets towards NET1.  Likewise
   ASY knows how to reach NET2.

   In order for traffic from NET2 to NET1 to flow between ASX and ASY,
   ASX has to announce NET1 to ASY using an exterior routing protocol;
   this means that ASX is willing to accept traffic directed to NET1
   from ASY. Policy comes into play when ASX decides to announce NET1 to
   ASY.

   For traffic to flow, ASY has to accept this routing information and
   use it.  It is ASY's privilege to either use or disregard the
   information that it receives from ASX about NET1's reachability. ASY
   might decide not to use this information if it does not want to send
   traffic to NET1 at all or if it considers another route more
   appropriate to reach NET1.

   In order for traffic in the direction of NET1 to flow between ASX and
   ASY, ASX must announce that route to ASY and ASY must accept it from
   ASX...
```
## ASN
An ASN is a unique identifier which organizations can use to connect to each other and be able to send and receive IP addresses which can further be distributed
### Public ASNs
Public ASNs are required for systems to exchange info over the internet
### Private ASNs
...can be used instead if a system is communicating solely w/ a single provider via [BGP](/networking/protocols/BGP.md) (Border GateWay Protocol).
### ASN Gateway:
How internal communication nodes (like w/i a business) connect to the global internet using ASN at one common point. 
#### Internal nodes
Each have their own IP addresses are connected through and [IGP](/networking/protocols/IGP.md) (Internal Gateway Protocol). The internal grouping of nodes is then connected to the larger internet using BGP.
>[!Resources]
> - [Data Tracker: RFC 1930](https://datatracker.ietf.org/doc/rfc1930/)
> - [Business Internet Services](https://neosnetworks.com/products-services/business-internet-services/what-are-autonomous-system-numbers/)
> - [Arin: ASN](https://www.arin.net/resources/guide/asn/)
> - [IP Location: ASN](https://www.iplocation.net/asn)
