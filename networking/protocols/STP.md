
# Spanning Tree Protocol
**Spanning Tree Protocol (802.1D):** This is an IEEE standard created in 1990 to *prevent loops* from happening b/w bridged/ switched networks. It is a *very common way* to prevent loops in networks.

Allows admins to *disable ports* between switches to prevent looping.
![](../../networking-pics/Pasted%20image%2020240712150138.png)
For example (using this diagram), the `Blocked Port` on Bridge 21 is preventing a loop from Bridge 6.
## Convergence Mode
STP is also good for troubleshooting outages b/w specific connections. For example, if the connection b/w Bridge 6 and Network A goes out, STP can put the network *into convergence mode*. In convergence mode STP analyzes the network to see what interfaces are working and which aren't.

Once it's discovered where the block is, it can make changes to which ports are configured and how to re-open a new path between Bridge 6 and Network A (like the Blocked Port on Bridge 11 becoming a Designated Port instead).
## BPDU
**Bridge Protocol Data Unit:** This is the primary protocol used in STP.
### BPDU Guard
One *issue* with spanning tree is it can take *several seconds* (20-30) for a switchport to determine how it should forward frames from a new device when it connects. If we're connecting a single device *then we don't have to worry that it will cause a loop*. But STP doesn't know that inherently.

You can configure the switch to know that the only thing that should be connecting to that interface *is an end station* (workstation) (doesn't make other connections), so the whole listening and learning processes can be skipped. Cisco calls this *PortFast*. The problem is that *if someone connects a switch to that port, a loop will be created*. 

This is where *BPDU (Bridge Protocol Data Unit) Guard* comes in. With BPDU Guard, the switch is *constantly watching the traffic* and if it sees a *BPDU frame* on a *PortFast* interface, then it knows that the device *is likely a switch* and it will *disable the interface* before a loop occurs.

> [!Resources]
> - [Professor Messer](https://www.youtube.com/watch?v=S_6ri7QM_Rc&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=110)
