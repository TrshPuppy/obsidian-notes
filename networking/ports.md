
# Ports:
Ports enforce what data can come in or leave from them and how.
- Has to be compatible
- Can also be used by networking devices to enforce strict rules on communication b/w one another.

## Port examples:
==There are 0 - 65,635 ports==
- Because there are so many, it's easy to lose track of which apps are running on which ports.
	- Applications/ software held to a standard of rules
		- ex: web browsers have to send data over #port-80 ( #HTTP)
- #Common-ports include all ports between 0 -1024

Some common ports:
|port|protocol|description|
|-|-|-|
|21| #FTP | see [[FTP]], #port-21 |
|22| #SSH | securely log into systems via text-interface, see #port-22 |
|80| #HTTP | for browsers and the #World-Wide-Web, see [[HTTP]], #port-80 |
|443| #HTTPS|same as port 80 but traffic is encrypted, see #port-443 |
|445| #SMB|similar to FTP, see [[SMB]], #port-445 |
|3389| #RDP| see [[RDP]], #port-3389 |

These ports follow standards, which means ==you can administer applications which interact with these protocols on different, non-standard ports==
- Have to provide a `:` w/ the port number bc applications will assume you are using standard ports

## Port Forwarding / #port-forwarding
If a device running a service on a port inside the #intranet of a network wants to make that service available to the public #internet, it can do so with port forwarding.
- configured by the ==network router==
- 

Below: the device at `192.168.1.10` is running a service on port 80. Only the other devices w/i the same intranet can access it:
![[Pasted image 20230211175427.png]]

Port forwarding:
![[Pasted image 20230211175531.png]]
-TryHackMe.com