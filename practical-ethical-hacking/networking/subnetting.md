
# Subnetting
Subnetting is an organizational technique used on networks break them up into sub networks. Subnetting works by taking advantage of [CIDR Notation](/networking/routing/CIDR.md) to re-delegate bits in an IP Address to serve either the host or the network.

## Subnet Mask:
The subnet mask tells you which parts of the IP address are network bits vs host bits. Each octet set to `255` in the subnet mask denotes an entire byte which belongs to the network. Each `0` in the subnet mask denotes bits belonging to the host:
```yaml
IP Address    : 192.168.32.5
Subnet Mask   : 255.255.255.0
CIDR Notation : 192.168.32.5/24

# According to the Subnet mask:
Network Bits : 192.168.32.x (total of 24 bits)
Host bits    : x.x.x.5      (total of 8 bits)
```

### Host bits:
The number of bits reserved for the host in an IP Address tells us *how many hosts* the network can support (how many devices can be on the network with their own unique IP Addresses).

In a `/24` network with 8 bits reserved for the host, 2^8 (256) hosts/devices can be on that network (minus 2 because the `0` address is reserved, usually for a router and counts as the first address).

### Wildcard Mask:
The wildcard mask is the inverted subnet mask. To create a wildcard mask you have to get the *bitwise complement* of the subnet mask in binary (i.e. all the 1 bits become 0, all the 0 bits become 1):
```yaml
IP Address (CIDR)    : 192.168.0.0/23
Subnet Mask          : 255.255.254.0
Subnet Mask (binary) : 11111111.11111111.11111110.00000000
Wildcard (binary)    : 00000000.00000000.00000001.11111111
Wildcard Mask        : 0.0.1.255
```
The Wildcard mask is useful when finding the address range of a subnet. For example, with a `/23` network, you know the subnet mask is `255.255.254.0` so the wildcard mask is `0.0.1.255`.

In the *third* octet, the only bit which can be flipped to make a unique address is the first bit (`0000000(1)`). It can either be `1` or `0`. The rest of the bits in the third octet are *not available* for address space (just like the bits in the first two octets).

Every bit in the fourth octet is available to be flipped to either a `1` or `0` giving a total of 2^8 (256) combinations and thus, 256 unique addresses.

This means that there are 256 possible addresses with the third octet set to `0` and 256 possible addresses with the third octet set to `1`. So the range of IP addresses for the address `192.168.0.0/23` is:
```yaml
Third octet set to 0 :
	Range : 192.168.0.0 - 192.168.0.255
Third octet set to 1 :
	Range : 192.168.1.0 - 192.168.1.255
```
For a total of 512 unique IP addresses.

## Changing the Subnet Mask:
Subnetting is just *changing the subnet mask* to allow for more networks to be supported by the IP Address. To create subnets in an IP address, bits are taken from the host portion of the address and "given" to the network portion.

Bits can only be taken from *least significant to most significant*:
```yaml
IP Address  : 192.168.32.5
Subnet Mask : 255.255.255.0 --> in binary: 11111111.11111111.11111111.00000000
# Bits cannot be taken from just anywhere in the subnet mask:
Wrong       : 11111111.11111111.11111111.00000(0)00
# Bits have to be taken starting on the left side (the left-most host bit):
Correct     : 11111111.11111111.11111111.(0)0000000
# The new subnet mask becomes:
Binary      : 11111111.11111111.11111111.10000000
Decimal     : 255.255.255.192
CIDR        : 192.168.32.5/25
```

### Deciding how many bits to take:
The number of bits taken from the network determines how many sub-networks can be created. The number of subnets possible = 2^(how many bits were taken).

*For example*: to create 4 subnets = 2^x. Solving for x gives us 2, meaning 2 bits need to be taken from the host bits to create 4 subnets.

*Example 2*: to create 17 subnets = 2^x. 2^4 = 16 (not enough, need one more bit) ==> 2^5 = 32, so 5 bits needed to be taken to create 17 sub networks.

## Subnets:
Once the subnet mask has been changed to support subnets, the range of each subnet can be determined. To figure out the range, you need the *increment.*

### Increment:
The increment (or the range of addresses each network belongs to) can be found by looking at the subnet mask:
```YAML
IP Address           : 192.168.32.5
Subnet Mask          : 255.255.255.192
Subnet Mask (binary) : 11111111.11111111.11111111.11000000
# The increment = the least significant network bit:
	Forth Octet      : 1    1    0    0    0    0    0    0
				      128  (64)  32   16   8    4    2    1
					 # the least sig network bit = 64 = the increment
```
Once you have the increment, you know that each subnet spans *increment* number of addresses. The subnet ranges in this example would be:
```yaml
Subnet 1 : 192.168.32.0 - 192.168.32.63
Subnet 2 : 192.168.32.64 - 192.168.32.127
Subnet 3 : 192.168.32.128 - 192.168.32.191
Subnet 4 : 192.168.32.192 - 192.168.32.255
```

### Reserved IPs w/i a Subnet:
In a subnet, the number of available hosts is always -2 the total possible addresses in the subnet. This is to account for the first and last addresses in the range, which are reserved for the Network ID and the Broadcast ID:

#### Network ID:
This is usually the first address in the sub netted range.

#### Broadcast ID:
Usually the last address in the range (but not always)
```yaml
IP Address       : 192.168.1.32/27
Subnet mask      : 255.255.255.224
Wildcard         : 0.0.0.31       <-- 32 possible addresses
Range            : 192.168.1.32 - 192.168.1.63
	Network ID   : 192.168.1.32
	Broadcast ID : 192.168.1.63
	Num of available addresses for hosts : 29
```

> [!Resources:]
> - [Network Chuck: Subnetting Playlist](https://www.youtube.com/watch?v=oZGZRtaGyG8&list=PLIhvC56v63IKrRHh3gvZZBAGvsvOhwrRF&index=5)
> - [subnetipv4.com](https://subnetipv4.com/)
> - [SuperUser: Answer about subnetting](https://superuser.com/questions/1126822/how-do-i-get-a-22-subnet-from-192-168-0-0-22-network-address)
> - [Wikipedia: Bitwise Operators](https://en.wikipedia.org/wiki/Bitwise_operation)
> - [Wikipedia: Wildcard Mask](https://en.wikipedia.org/wiki/Wildcard_mask)
> - [Subnet Calculator](https://www.subnet-calculator.com/wildcard.php)

> [!My previous notes (linked in the text):]
> - [CIDR Notation](https://github.com/TrshPuppy/obsidian-notes/blob/main/networking/routing/CIDR.md)


