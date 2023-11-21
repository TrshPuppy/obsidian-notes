
# Ping Command
Test to see whether a connection to a remote resource is possible.

## Usage:
```
ping <target>
```

### Useful options:
`ping-i:`
- interval: allows for setting an interval in seconds between ea packet.
- ex:
- ``ping google.com -i 5`` <-- packet sent q 5 seconds
`ping-v`:
- verbose
`ping-c`:
- count: stop sending after `count` number of ECHO_REQUEST packets.
`ping-4` & `ping-6`:
- use IPv4 or IPv6 only

## About:
Uses the [ICMP](/networking/protocols/ICMP.md) protocol.
- sends an "ICMP ECHO_REQUEST" to network hosts.
- one of the less-well known `TCP/IP` protocols.
- works on the [network-layer](/networking/OSI/network-layer.md) of the [OSI-reference-model](/networking/OSI/OSI-reference-model.md)

Returns the IP address of the target that it connected to.
- Can be used to determine the IP address of the server hosting a website
- ex:
```
ping google.com
PING google.com (216.158.198.174) 56(48) bytes of data.  <--- response
```

==All operating systems support ping out of the box==
- even embedded devices