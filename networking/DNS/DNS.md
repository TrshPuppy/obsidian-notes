
# Domain Name System
a #TCP/IP protocol which allows a device to ask a #DNS server for the #IP-address attached to a #domain-name.

## Domain Hierarchy:
![](/networking/networking-pics/DNS-1.png)
-[Try Hack Me](https://tryhackme.com/room/dnsindetail)

### Top Level Domain:
Most right-hand part of the domain name (`.com` is the #TLD of `tryhackme.com`)

##### #gTLD:
A Generic Top Level Domain is meant to tell the user the domain name's purpose (like .com for commercial, .edu for education)

##### #ccTLD:
Used for geographical purposes (`.ca` for Canada)

### Second Level Domain:
The second level domain in `tryhackme.com` would be `tryhackme`. It's limited to 63 characters + the TLD and can only use a-z and 0-9. Also cannot start or end with hyphens or have consecutive hyphens.

### Subdomain:
A #subdomain is additional info added to the beginning of a website's domain name. It allows the site to be separated and organized into specific contents and functions.

Ex: `hackthebox.com` vs `ctf.hackthebox.com`. -->`ctf` is the subdomain and it still under `hackthebox`'s domain.

*Subdomains can have different IP addresses* and all of the subdomains of one domain can be handled by one server using #virtual-host-routing where the servers uses the #host-header in the HTTP request to determine which app is meant to handle which request.

#### Subdomain Enumeration:
In order to find all the subdomains on a virtual host, tools like [Gobuster](/cybersecurity/tools/gobuster.md) can perform #subdomain-enumeration. Using a wordlist of possible subdomains, Gobuster will send out an HTTP request with a host header (of the vhost) to all the addresses w/ the possible subdomains appended.
```
Host: [word].thetoppers.htb
```

## Steps w/ example:
You type `www.twitch.com` into your browser:
1. computer checks its local #cache to see if it already knows the IP address stored for that website
	- if it does: great
	- if it doesn't: go to step 2
2. Computer sends a request to a #recursive-DNS-server:
	- Automatically known to the router on the network b/c #ISPs maintain their own recursive servers
		- Companies like google also have recursive servers
		- how your computer knows where to send requests for information
3. If the domain is NOT in the recursive server:
	- computer will send to a #root-name-server
		- Used to only 13 for entire world
		- now there are more but they will use the same 13 IP addresses assigned to the original servers
			- IPs are balanced so you get to the closest server to your request
	- Root servers keep track of the DNS servers in the next level down( #top-level-domain servers)
4. #Top-level-domain-servers (TLDs) are split up into extensions
	- ex: when searching for `twitch.com` the request is re-routed to a #TLD that handles `.com` domains
	- TLD servers keep track of the next level below them: #Authoritative-Name-Servers
5. Authoritative Name Servers:
	- used to store DNS records for domains directly.
		- (ever DNS record in the world is stored on an Authoritative name server)
		- ==the source of the information==
	- When a request reaches the #ANS it sends the relevant info back to your computer.

## Dig / [dig](/CLI-tools/dig.md) command:
The dig command allows you to manually query recursive DNS servers for info about domains