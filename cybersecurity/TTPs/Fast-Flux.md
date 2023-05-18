
# Fast Flux
Used by a threat actor to hide malicious activity using compromised hosts on a #botnet
- first introduced by [storm-worm](/cybersecurity/malware/storm-worm.md) in 2006
- usually used to make the connection between #malware and its #command-and-control center harder to discover.![](/cybersecurity/cybersecurity-pics/fast-flux-1.png)
>"To understand the boundaries and relations between the network entities, an undirected network graph was created (Figure 2). The graph represents the following entities and relations between them: domains (shown in red), IP addresses (purple), and nameservers (green). The inspected network is composed of two subnetworks sharing a strong relation. These subnetworks are connected based on the similarity between their shared IP addresses associated with different nameservers." 

\- [Akamai](https://www.akamai.com/blog/security/digging-deeper-an-in-depth-analysis-of-a-fast-flux-network)

### Primary Characteristics:
1. a #fast-flux network constantly changes its #domain s, #IP-addresses and #nameservers 
	- hides the true nature of the network making it harder to study and defend against
	- #### IP-addresses:
		- the amount of #IP-addresses associated w/ a #fast-flux network change rapidly.
			- Also called #single-flux
			- ![](/cybersecurity/cybersecurity-pics/fast-flux-2.png)] 
			- This image shows the avg number of times #IP-addresses associated a single #DNS-name changed in one day (over 2 months) - [Akamai](/cybersecurity/literature/Akamai.md)
	- #### Domains:
		- threat actors cycle between making #domains in the network active vs inactive 
			- considered inactive when a #DNS-query returned w/ "NXDOMAIN"
		- #domains stay active for a limited time while malicious activity is taking place. 
			- once the malicious activity associated w/ that #domain ended, it would be inactivated and a new domain would be activated to ensure network services remained intact
				- this is called #double-flux
			- ![](/cybersecurity/cybersecurity-pics/fast-flux-6.png) 
			- #double-flux ensures redundancy and survivability w/i the network
				- following the #DNS-trail and shutting down servers/#domains used by the #botnet does not end the activities of the larger #botnet 
	- #### Nameservers :
		- #nameservers associated w/ the #fast-flux-network are are usually registered to different entities, rotated in and out of usage, and registered to owners w/ spoofed personal information:
		- ![](/cybersecurity/cybersecurity-pics/fast-flux-3.png) 
		- ![](/cybersecurity/cybersecurity-pics/fast-flux-4.png) 
		- even though the faked-personal information of the alleged owners of different #nameservers seem unrelated (different countries, etc) analysis of their #IP-addresses prove they are actually *closely related* #nameservers 

### C2 network vs hosting-network:

![](/cybersecurity/cybersecurity-pics/fast-flux-5.png)
>"To further investigate the initial assumption of having two different subnetworks as observed in “Fast Flux network — overview”, we created a network graph, but this time without showing the relation to the name-server. Doing that showed us that we can see two distinct subnetworks segregated in terms of associated IP addresses." 

\-[Akamai](https://www.akamai.com/blog/security/digging-deeper-an-in-depth-analysis-of-a-fast-flux-network) 

>[!links]
> [Akamai: Fast-Flux](https://www.akamai.com/blog/security/digging-deeper-an-in-depth-analysis-of-a-fast-flux-network)
> 
> [Fast Flux 101](https://unit42.paloaltonetworks.com/fast-flux-101/)