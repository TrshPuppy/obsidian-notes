
# Traceroute Command
Used to map the path your request takes to its target machine. On Linux, this command operates over [UDP](/networking/protocols/UDP.md) but can be altered to use something else w/ switches.

## Usage:
```
traceroute <destination> [OPTIONS]
```

### Useful options:
#### `traceroute -i`:
Specify an interface which traceroute should use to send packets. *Default:* will use the computer's [routing table](/networking/routing/routing-table.md).

#### `traceroute -T` & `traceroute -I`:
The `-T` flag will let you probe using [TCP](/networking/protocols/TCP.md) SYN packets.

The `-I` flag will let you use an [ICMP](/networking/protocols/ICMP.md) ([ping](ping.md)) `ECHO_REQUEST` to probe the route.

### On Windows:
The equivalent command is `tracert` and it also uses ICMP protocol, similar to `ping`.

> [!Resources:]
> - [Try Hack Me: Intro to Networking](https://tryhackme.com/room/introtonetworking)




