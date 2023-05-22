
# Linux Network Commands
The `ip` and `ifconfig` commands are similar. They list and configure current network interfaces on the device. `ifconfig` is the older of the two and may not be present on all machines.

Using `ip a` will list both wireless *and* hard-wired/ ethernet connections, while `ifconfig` will only list ethernet. Another command you can use to list wireless connections is `iwconfig`.

## [ARP](/networking/protocols/ARP.md) (Address Resolution Protocol)
Address Resolution Protocol is a [layer 3](/networking/OSI/network-layer.md) protocol which helps a host resolve an IP address into the MAC address of the associated device. 

The `arp -a` and the `ip n` (`n` stands for `neighbor`) commands can be used in Linux to list the MAC Addresses associated with local IP addresses in the network.

## [Routing Tables](/networking/routing/routing-tables.md)
When you're on a network, it's good to know the routing tables. The routing tables of a network can tell you about the topology of the network. 

For example, if you're IP Address is a /24, you expect 256 possible addresses in that subnet. Checking the routing table, you may find additional addresses, outside your subnet meaning *you may be able to access those other networks.*

Both of the following commands will show you the routing table of the network you're on:
- `route` command
- `ip r` command
- `netstat -rn` command

Networks can also be *added to a routing table* allowing you to gain access to it.

## [ICMP (Internet Control Message Protocol)](/networking/protocols/ICMP.md)
A layer 3 protocol used between IP addressable devices to check the status of a host/ device. 

Using the [`ping` command](/CLI-tools/ping.md) on either a Linux or Windows machine will tell you whether that device is connected and able to respond. On Windows, `ping` will only send a set amount of packets to the target, whereas on Linux `ping` will continuously send packets unless you use `SIGINT` or tell the command how many packets to send.

`ping` will also give you the time in milliseconds it took to get a response from the target, as well as how many bytes were sent in the ping request.

> [!My previous notes (linked in text)]
> - [ARP](https://github.com/TrshPuppy/obsidian-notes/blob/main/networking/protocols/ARP.md)
> - [Routing Tables](https://github.com/TrshPuppy/obsidian-notes/blob/main/networking/routing/routing-table.md)
> - [ICMP](https://github.com/TrshPuppy/obsidian-notes/blob/main/networking/protocols/ICMP.md)
> - [ping command](https://github.com/TrshPuppy/obsidian-notes/blob/main/CLI-tools/ping.md)

