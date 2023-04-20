
# Traceroute Command
Used to map the path your request takes to its target machine.

## Usage:
```
traceroute <destination> [OPTIONS]
```

### Useful options:
#traceroute-i:
- specify an interface which traceroute should use to sent packets.
	- default: will use the routing table
#traceroute-T & #traceroute-I:
- use #TCP/SYN for probes OR
- use ICMP ECHO_REQUEST for probes

## About:
Windows:
- `tracert`
- uses [ICMP](/networking/protocols/ICMP.md) protocol (like [ping](/CLI-tools/ping.md))

Linux:
- operates over [UDP](/networking/protocols/UDP.md)
==Can be altered w/ switches in both contexts==

