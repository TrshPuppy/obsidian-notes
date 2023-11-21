---
aliases: [ASN, Autonomous-System, Autonomous-System-Number]
---
# Autonomous System Number
- An #autonomous-system is a "set of routers under a single technical administration, using an interior gateway protocol and common metrics to route packets to other ASes."
	- it is a "connected group of one or more #IP-prefixes run by one or more network operators which has a SINGLE and CLEARLY DEFINED #routing-policy"
		- #routing-policy : how routing decisions are made

from #RFC-1930 :
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

>[!link]
>https://neosnetworks.com/products-services/business-internet-services/what-are-autonomous-system-numbers/

An #ASN is a unique identifier which two organizations can use to connect to each and be able to send and receive #IP-addresses  which can further be distributed
- can be public or private
	- #public-ASNs are required for systems to exchange info over the internet
	- #private-ASNs can be used instead if a system is communicating solely w/ a single provider via [BGP](/networking/protocols/BGP.md) (Border GateWay Protocol).
- #ASN-gateway:
	- how internal communication nodes (like w/i a business) connect to the global internet at one common point, using an #ASN 
	- #internal-nodes each have their own #IP-address are connected through and [IGP](/networking/protocols/IGP.md) (Internal Gateway Protocol)
	- the internal grouping of nodes is then connected to the larger internet using #BGP 

>[!related]
> #RFC-1930

>[!links]
>https://datatracker.ietf.org/doc/rfc1930/
