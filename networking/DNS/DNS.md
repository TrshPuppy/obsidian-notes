
# Domain Name System
DNS is a [TCP/IP](/networking/protocols/TCP.md) protocol which allows a device to ask a name server for the [IP address](/networking/OSI/IP-addresses.md) attached to a domain name.
## Domain Hierarchy:
![](/networking/networking-pics/DNS-1.png)
-[Try Hack Me](https://tryhackme.com/room/dnsindetail)
### Top Level Domain:
Most right-hand part of the domain name. For example, `.com` is the TLD of `tryhackme.com`.
##### gTLD (Generic TLD):
A Generic Top Level Domain is meant to tell the user the *domain name's purpose* (like `.com` for commercial, `.edu` for education)
##### ccTLD :
Used for geographical purposes (`.ca` for Canada)
### Second Level Domain:
The second level domain in `tryhackme.com` would be `tryhackme`. It's limited to 63 characters + the TLD and *can only use a-z and 0-9.* Also cannot start or end with hyphens or have consecutive hyphens.
### Subdomain:
A subdomain is additional info added to the beginning of a website's domain name. *It allows the site to be separated and organized* into specific contents and functions.

Ex: `hackthebox.com` vs `ctf.hackthebox.com`. -->`ctf` is the subdomain and it still under `hackthebox`'s domain.

*Subdomains can have different IP addresses* and all of the subdomains of one domain can be handled by one server using *virtual host routing* where the server uses the *Host* header in the [HTTP](/networking/protocols/HTTP.md) request to determine which app is meant to handle which request.
#### [Subdomain Enumeration](nested-repos/PNPT-study-guide/PEH/recon/hunting-subdomains.md):
In order to find all the subdomains on a virtual host, tools like [Gobuster](cybersecurity/tools/scanning-enumeration/gobuster.md) can perform subdomain enumeration Using a wordlist of possible subdomains, Gobuster will send out an HTTP request with a host header (of the vhost) to all the addresses w/ the possible subdomains appended.
```
Host: [word].thetoppers.htb
```
## Domain/Hostname Resolution
There is a series of step a device takes in order to resolve a hostname (like `www.twitch.tv`) into an IP address:
### Initial Hostname Request
You type `www.twitch.tv` into your browser.
### Computer checks local cache
Your computer checks its *local cache* to see if it already knows the IP address stored for that website. If it does, great. If it doesn't?
### Computer sends a request out...
If the computer doesn't have the hostname in its local cache, it forwards the request to a *Recursive Domain name Server.*

The IP address of the recursive server is already known by the router on the computer's network. This is because *ISPs maintain their own recursive servers.* Large companies like Google also have their own recursive servers. This is how your computer *knows where to send resolution requests.*
### If the domain is *NOT* in the RDS:
The request will be forwarded to the *Root Name Server*. Root name servers keep track of the DNS servers in the next level down, the *Top Level Domain Servers*.

There used to only be *13 for the entire world*, now there are more but the original 13 continue to keep the same 13 IP addresses. The IP addresses of these servers are balanced *so you get to the closest server to your request.*
### The relevant Root NS...
forwards the request to the relevant *Top Level Domain* it keeps track of. In this case, the TLD which *keeps track of the `.tv` domains.*
#### Top Level Domain Servers (TLDs)
TLDs are split up into extensions. For example, when searching for `twitch.tv` the request is re-routed to a TLD that *handles the `.tv` namespace.*

TLD servers are responsible for *keeping track of the next level below them*; Authoritative Name Servers.
	- ex: when searching for `twitch.com` the request is re-routed to a #TLD that handles `.com` domains
	- TLD servers keep track of the next level below them: #Authoritative-Name-Servers
### The TLD queries the Authoritative Name Servers:
*Authoritative Name Servers* store DNS records for domain directly. Every DNS record in the world *is stored on an ANS*.

An ANS is the final *source of information when resolving a domain name*. Once the correct ANS is found, it will fill in the IP address matching the original request, and this information *gets sent back to your computer.*

> [!Resources]
> - [TryHackMe: DNS in Detail](https://tryhackme.com/room/dnsindetail)

> [!Related]
> - Commands: [dig](/CLI-tools/dig.md), [whois](/CLI-tools/whois.md)
> - Tools: [amass](/cybersecurity/tools/scanning-enumeration/amass.md)
