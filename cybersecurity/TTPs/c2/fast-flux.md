
# Fast Flux
Used by a threat actor to hide malicious activity using compromised hosts on a [botnet](/cybersecurity/TTPs/botnet.md). This TTP was first introduced by [storm-worm](/cybersecurity/malware/storm-worm.md) in 2006 and is effective at making the connection between malware and its [C2C](/cybersecurity/TTPs/C2C.md) harder to discover.
![](/cybersecurity/cybersecurity-pics/fast-flux-1.png)
>	"To understand the boundaries and relations between the network entities, an undirected network graph was created (Figure 2). The graph represents the following entities and relations between them: domains (shown in red), IP addresses (purple), and nameservers (green). The inspected network is composed of two subnetworks sharing a strong relation. These subnetworks are connected based on the similarity between their shared IP addresses associated with different nameservers." 
>	\- [Akamai](https://www.akamai.com/blog/security/digging-deeper-an-in-depth-analysis-of-a-fast-flux-network)

## Primary Characteristics:
A fast flux network hides the origin of its C2 by constantly changing its [domains](/networking/DNS/DNS.md), [IP addresses](/networking/OSI/IP-addresses.md), and [nameservers](/networking/DNS/DNS.md). This allows it to hide the true nature of the network by making it harder to study and defend against.

### IP Addresses
The amount of IP addresses associated w/ a fast flux network changes rapidly.
![](/cybersecurity/cybersecurity-pics/fast-flux-2.png)
>	This image shows the avg number of times IP addresses associated a single domain name changed in one day (over 2 months) - [Akamai](/cybersecurity/literature/Akamai.md)

### Domains:
Threat actors cycle between making activating and deactivating domains in the network. A domain is considered inactive when a DNS query returns w/ `NX-DOMAIN`.

#### Double-flux
When the threat actor activates a domain, it stays active for a limited time while malicious activity is taking place. Once the malicious activity associated w/ that ends its deactivated again and a new domain is activated to take its place. This is to ensure network services remained intact. This is called *"Double Flux"*.

![](/cybersecurity/cybersecurity-pics/fast-flux-6.png) 

Double Flux ensures redundancy and survivability w/i the network. Following the DNS trail and shutting down servers/domains used by the botnet *does not end the activities of the larger botnet*.

### Nameservers :
Nameservers associated w/ the fast flux network are are usually registered to different entities, rotated in and out of usage, and registered to owners w/ spoofed personal information:

![](/cybersecurity/cybersecurity-pics/fast-flux-3.png) 
![](/cybersecurity/cybersecurity-pics/fast-flux-4.png) 
>	Akamai

Even though the faked-personal information of the alleged owners of different nameservers seem unrelated (different countries, etc) analysis of their IP addresses proves they are actually *closely related* nameservers.

## C2 network vs hosting-network:
![](/cybersecurity/cybersecurity-pics/fast-flux-5.png)
>	"To further investigate the initial assumption of having two different subnetworks as observed in “Fast Flux network — overview”, we created a network graph, but this time without showing the relation to the name-server. Doing that showed us that we can see two distinct subnetworks segregated in terms of associated IP addresses." 
>	\- [Akamai](https://www.akamai.com/blog/security/digging-deeper-an-in-depth-analysis-of-a-fast-flux-network) 

>[!Resources]
> - [Akamai: Fast-Flux](https://www.akamai.com/blog/security/digging-deeper-an-in-depth-analysis-of-a-fast-flux-network)
> - [UInt42: Fast Flux 101](https://unit42.paloaltonetworks.com/fast-flux-101/)
