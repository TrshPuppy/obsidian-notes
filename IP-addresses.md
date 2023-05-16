
# IP Addresses
Local path: [IP Addresses](/networking/OSI/IP-addresses.md) 
GitHub path: [IP Addresses](https://github.com/TrshPuppy/obsidian-notes/blob/main/networking/OSI/IP-addresses.md)

## IPv4 vs IPv6:
Possible amount of IP addresses = 32 bits (2^32) = about 4 billion addresses. *We have already run out of addresses using IPv4.*

### IPv6:
Instead of using 32 bits to create IP addresses, we use hexadecimal notation to create 128 bits (2^128) for addresses (a much larger amount which we will likely never use up).

### Network Address Translation:





IP addresses are organized into classes (A, B, C, D...) which differ based on how the network and host bits are allocated. For example, Class A addresses have 126 bits allocated to the network and 16,600,000+ to the host.

Class A:
```
Network Numbers: 10.0.0.0
Network Mask: 255.0.0.0
```

Class C addresses are reserved for private use (within households, etc.). Compared w/ Class A, the Class C IP range allows for less hosts (254), but more networks (2,000,000+):
```
Range: 192.168.0.0 to 192.168.255.255
Network Mask: 255.255.255.0
```

This class system has temporarily mitigated the issue of running out of IPv4 addresses because it allows for ranges (Class C) to be used by multiple people/ organizations, while public classes (Class A) cannot be used by more than one source simultaneously.