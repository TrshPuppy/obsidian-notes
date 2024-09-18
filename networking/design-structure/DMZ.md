
# Demilitarized Zone (DMZ)
A DMZ is a network segment which *sits between the internal network and the wider internet*. The DMZ is used as a  buffer and is usually considered *insecure*. It's purpose is normally to add an extra layer of security between the internal network and an insecure network like the internet. It isolates public-facing servers on the network from the internal network and allows controlled *access to public resources*.
![](../networking-pics/DMZ-1.jpg)
## Resources Places in the DMZ
The following are resources which are *commonly placed in the DMZ:*
### Web Servers
Any websites which are *accessible to the public* can be placed in the DMZ to separate them from internal, critical or sensitive systems. 
### Mail Servers
Email servers commonly interact with external networks, so they are usually placed within a DMZ.
### [Proxy](proxy.md) Servers
Usually act as intermediaries between internal devices and users and external networks like the internet.
### Public Facing Applications
Any applications or services which are public facing should be placed in the DMZ so they can be isolated from the internal network.

> [!Resources]
> - Internship learning material

