
# Domain Name System
a #TCP/IP protocol which allows a device to ask a #DNS server for the #IP-address attached to a #domain-name.

# Steps w/ example:
You type `www.twitch.com` into your browser:
1. computer checks its local #cache to see if it already knows the IP address stored for that website
	- if it does: great
	- if it doesn't: go to step 2
2. Computer sends a request to a #recursive-DNS-server:
	- Automatically known to the router on the network b/c #ISPs maintain their own recursive servers
		- Companies like google also hae recursive servers
		- how your computer knows where to send requests for information
3. If the domain is NOT in the recursive server:
	- computer will send to a #root-name-server
		- Used to only 13 for entire world
		- now there are more but they wtill use the same 13 IP addresses assigned to the original servers
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

## Dig / [[dig]] command:
The dig command allows you to manually query recursive DNS servers for info about domains