
# Domain Name System
DNS is a [TCP/IP](/networking/protocols/TCP.md) protocol which allows a device to ask a name server for the [IP address](/networking/OSI/3-network/IP-addresses.md) attached to a domain name.
## Components
The DNS system is made up of three main components:
### Namespace and Resource Records
> The DOMAIN NAME SPACE and RESOURCE RECORDS, which are	specifications for a tree structured name space and data	associated with the names.  Conceptually, each node and leaf	of the domain name space tree names a set of information, and	query operations are attempts to extract specific types of information from a particular set.  A query names the domain name of interest and describes the type of resource information that is desired.  For example, the Internet	uses some of its domain names to identify hosts; queries for address resources return Internet host addresses.
> - [RFC 1034](https://datatracker.ietf.org/doc/html/rfc1034)
### Name Servers
>  NAME SERVERS are server programs which hold information about the domain tree's structure and set information.  A name server may cache structure or set information about any part of the domain tree, but in general a particular name server  has complete information about a subset of the domain space, and pointers to other name servers that can be used to lead to information from any part of the domain tree.  Name servers know the parts of the domain tree for which they have complete information; a name server is said to be an AUTHORITY for these parts of the name space.  Authoritative information is organized into units called ZONEs, and these zones can be automatically distributed to the name servers which provide redundant service for the data in a zone.
  - [RFC 1034](https://datatracker.ietf.org/doc/html/rfc1034)
### Resolvers
> RESOLVERS are programs that extract information from name servers in response to client requests.  Resolvers must be able to access at least one name server and use that name server's information to answer a query directly, or pursue the query using referrals to other name servers.  A resolver will typically be a system routine that is directly accessible to user programs; hence no protocol is necessary between the resolver and the user program.
  - [RFC 1034](https://datatracker.ietf.org/doc/html/rfc1034)
## Namespace
The domain name system (DNS) is hierarchical “tree” structure with nodes and leaves. Resources in the name space correspond to either a node or a leaf. Each node/ leaf has a label which can be anywhere from 0 to 63 octets in length. Two nodes which are related (or 'brothers') cannot have the same name, but two nodes which aren't related can.

A node's domain name *is the list of labels on the path from the node itself to the root domain*. The root domain label is reserved and has a length of 0 (which makes it null). All domain names end at the root *which effectively uses a null string as its label*. Doman names are *case insensitive* (meaning `A` and `a` as domain names would be a collision if they are brothers).
### Example Namespace Hierarchy
```rfc
                                   |
                                   |
             +---------------------+------------------+
             |                     |                  |
            MIL                   EDU                ARPA
             |                     |                  |
             |                     |                  |
       +-----+-----+               |     +------+-----+-----+
       |     |     |               |     |      |           |
      BRL  NOSC  DARPA             |  IN-ADDR  SRI-NIC     ACC
                                   |
       +--------+------------------+---------------+--------+
       |        |                  |               |        |
      UCI      MIT                 |              UDEL     YALE
                |                 ISI
                |                  |
            +---+---+              |
            |       |              |
           LCS  ACHILLES  +--+-----+-----+--------+
            |             |  |     |     |        |
            XX            A  C   VAXA  VENERA Mockapetris
```
In this hierarchy, the root domain has three subdomains, `MIL`, `EDU`,  and `ARPA`.  These are 'brother' domains. `LCS.MIT.EDU` has one subdomain called `XX.LCS.MIT.EDU`.  This diagram is in RFC 1034.
## Domain Hierarchy:
![](/networking/networking-pics/DNS-1.png)
-[Try Hack Me](https://tryhackme.com/room/dnsindetail)
### Top Level Domain
Most right-hand part of the domain name. For example, `.com` is the TLD of `tryhackme.com`.
##### gTLD (Generic TLD)
A Generic Top Level Domain is meant to tell the user the *domain name's purpose* (like `.com` for commercial, `.edu` for education)
##### ccTLD 
Used for geographical purposes (`.ca` for Canada)
### Second Level Domain
The second level domain in `tryhackme.com` would be `tryhackme`. It's limited to 63 characters + the TLD and *can only use a-z and 0-9.* Also cannot start or end with hyphens or have consecutive hyphens.
### Subdomain
A subdomain is a prefix added to a domain name. It allows the domain to be separated and organized into specific contents and functions. For example, the `hackthebox.eu` domain has a subdomain named `ctf` . To access this subdomain, you would visit `ctf.hackthebox.eu`. From the name, you can tell that this is where HackTheBox hosts all of their CTF related services.

*Subdomains can have different IP addresses* and all of the subdomains of one domain can be handled by one server using *virtual host routing* where the server uses the *Host* header in the [HTTP](/www/HTTP.md) request to determine which app is meant to handle which request.
#### [Subdomain Enumeration](PNPT/PEH/recon/hunting-subdomains.md)
In order to find all the subdomains on a virtual host, tools like [Gobuster](../../cybersecurity/TTPs/recon/tools/dir-and-subdomain/gobuster.md) can perform subdomain enumeration Using a wordlist of possible subdomains, Gobuster will send out an HTTP request with a host header (of the vhost) to all the addresses w/ the possible subdomains appended.
```
Host: [word].thetoppers.htb
```
## Domain/Hostname Resolution
There is a series of steps a device takes in order to resolve a hostname (like `www.twitch.tv`) into an IP address:
### Initial Hostname Request
You type `www.twitch.tv` into your browser.
### Computer checks local cache
Your computer checks its *local cache* to see if it already knows the IP address stored for that website. If it does, great. If it doesn't?
### Computer sends a request out...
If the computer doesn't have the hostname in its local cache, it forwards the request to a *Recursive Domain name Server.*

The IP address of the recursive server is already known by the router on the computer's network. This is because *ISPs maintain their own recursive servers.* Large companies like Google also have their own recursive servers. This is how your computer *knows where to send resolution requests.*
### If the domain is *NOT* in the RDS
The request will be forwarded to the *Root Name Server*. Root name servers keep track of the DNS servers in the next level down, the *Top Level Domain Servers*.

There used to only be *13 for the entire world*, now there are more but the original 13 continue to keep the same 13 IP addresses. The IP addresses of these servers are balanced *so you get to the closest server to your request.*
### The relevant Root NS...
forwards the request to the relevant *Top Level Domain* it keeps track of. In this case, the TLD which *keeps track of the `.tv` domains.*
#### Top Level Domain Servers (TLDs)
TLDs are split up into extensions. For example, when searching for `twitch.tv` the request is re-routed to a TLD that *handles the `.tv` namespace.*

TLD servers are responsible for *keeping track of the next level below them*; Authoritative Name Servers.
	- ex: when searching for `twitch.com` the request is re-routed to a #TLD that handles `.com` domains
	- TLD servers keep track of the next level below them: #Authoritative-Name-Servers
### The TLD queries the Authoritative Name Servers
*Authoritative Name Servers* store DNS records for domain directly. Every DNS record in the world *is stored on an ANS*.

An ANS is the final *source of information when resolving a domain name*. Once the correct ANS is found, it will fill in the IP address matching the original request, and this information *gets sent back to your computer.* 
#### NOERROR
`NOERROR` is the response returned from nameservers and recursive DNS servers when the domain *is successfully resolved*. Attached to this response will be the resolved IP address.
#### NXDOMAIN
`NXDOMAIN` is a DNS error message sent as a response from a DNS request *when the requested domain name doesn't exist*. Only an *Authoritative Name Server* can return `NXDOMAIN`.

> [!Resources]
> - [TryHackMe: DNS in Detail](https://tryhackme.com/room/dnsindetail) 
> - [ClouDNS: What is NXDOMAIN](https://www.cloudns.net/blog/what-is-nxdomain/#NXDOMAIN_%E2%80%93_Definition)
> - [RFC 1034](https://datatracker.ietf.org/doc/html/rfc1034) (on domain name concepts)
> - [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) (on implementation and specifications)

> [!Related]
> - Commands: [dig](/CLI-tools/dig.md), [whois](/CLI-tools/whois.md)
> - Tools: [amass](../../cybersecurity/TTPs/recon/tools/dir-and-subdomain/amass.md)
> - `port 53`
> - [DNS tunneling](../../OSCP/tunneling/DNS-tunneling.md)
> - [`dnsmasq`](../../OSCP/tunneling/DNS-tunneling.md#`dnsmasq`)
