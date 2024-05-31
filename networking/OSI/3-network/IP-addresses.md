
# Internet Protocol Addresses
An IP Address is 4 binary octets separated by periods. IP addresses are used in [Layer 3](/networking/OSI/3-network/network-layer.md) of the [OSI Reference Model](/networking/OSI/OSI-reference-model.md) to transmit data between devices on a network.

Each device on a network is allocated a unique IP Address which identifies it. Depending on how the IP Addresses are allocated a device could keep the same IP address over a long period of time (static), or be allocated a new one which will only last for a pre-configured amount of time ([DHCP](/networking/protocols/DHCP.md)).

Regardless of allocation, two devices on the same network *cannot share the same IP address.*
## Format
![](/networking/networking-pics/IP-addresses-1.png)
> [Try Hack Me](https://tryhackme.com/room/whatisnetworking)

An IPv4 address is arranged into 4 octets. While it is normally notated in base 10, the numbers represent the actual binary values of each octet.
```
Base 10 notation:   192.168.1.1
Binary notation :   11000000.10101000.00000001.00000001
```
With all bits in each octet equal to 1, the base 10 notation looks like this:
```
255.255.255.255
```
So, each octet can support 0-255. However, pre-determined ranges are used to reserve IP Addresses for specific assignments. For example, `192.168.0.0` thru `192.168.255.255` is reserved for private use.
### [CIDR](/networking/routing/CIDR.md) Notation
The bits in an IP address can be divided into "host bits" and "network bits". The number of bits designated to the network make up the left side of the address, and the number of bits designated to the host make up the right side.

Using CIDR notation, you can tell where the division in the IP Address is. CIDR notation is the IP Address followed by a `/x` with `x` being the number of bits which belong to the network.

For example:
```
IP Address: 172.16.23.202
CIDR notation: 172.16.23.202/24

First 24 bits: 172.16.23 ==> the Network portion of the address
Remaingin 8 bits: 202 ==> the Host portion of the address
```
By using CIDR notation, we can tell that this IP address can support 255 hosts (devices), meaning it can assign 254 unique IP addresses (`192.168.23.1` thru `192.168.23.255`).

CIDR notation is also used in [subnetting](PNPT/PEH/networking/subnetting.md) because it makes it easy to re-allocate network bits to the host, thus creating subnets under one IP Address.
## Namespace (public vs private)
There are both private and public IP Address ranges. This practice has helped to prevent IP Address Exhaustion (since 4 octets can only support 4 billion unique addresses). By splitting the IP ranges into private vs public, separate private networks can make use of the same IP Address namespace without collision.

Public IP addresses are the "public-facing" addresses of a network. Because they are public facing (and not concealed w/i a private network) they have to be unique and cannot be shared. Internet Service Providers provide a unique IP to clients, usually for a monthly fee.

Private IP Addresses are used to identify devices on a shared, local network.
### Public IP Ranges & Classes:
#### Class A:
- `1.0.0.0` to `9.255.255.255`
- `11.0.0.0` to `126.255.255.255`
#### Class B:
- `128.0.0.0` to `172.15.255.255`
- `172.32.0.0` to `191.255.255.255`
#### Class C:
- `192.0.0.0` to `192.167.255.255`
- `192.169.0.0` to `223.255.255.255`
### Private IP Ranges/ Classes:
#### Class A
`10.0.0.0` to `10.255.255.255`
#### Class B
`172.16.0.0` to `172.31.255.255`
#### Class C
`192.168.0.0` to `192.168.255.255`
## IPv4 vs IPv6
### IPv4 Exhaustion
IPv4 addressing (`xxx.xxx.xxx.xxx`) only supports about 4 billion unique addresses. This is because each address is made up of a total of 32 bits (2^32 possible addresses). According to Cisco, by 2021 there were ~ 50 billion connected devices, meaning we have run out of IP Addresses.
#### Private IPs
Splitting the ranges into private and public ranges helps with exhaustion because private addresses can be used multiple times within a single network (as long as there is segmentation and layering, etc.).
#### [Subnetting](../../../PNPT/PEH/networking/subnetting.md)
Subnetting allows for more efficient use of IP addresses by *borrowing host bits from the address* and giving them *to the network portion of the address.* This effectively turns one address range (like `192.168.14.0/24`) into two *subnets*:
- subnet one: `192.168.14.0/25` 
- subnet two: `192.168.14.128/25`

The CIDR notation goes from `/24` to `/25` because we've *taken one host bit* and given it *to the network*. `/25` gives us two subnets.
#### DHCP
DHCP also helps w/ IPv4 exhaustion because it frees up IP addresses which are not being used. When a device previously assigned an IP address thru DHCP leaves a network , that address returns to an *address pool* where it can be used for the next device which connects.
#### IPv6
IPv6 is a new way to notate IP addresses and was developed to expand the available address space for devices on a network/ the internet.

Instead of being made up of 32 bits, notated in base 10, IPv6 is 128 bits notated in hexadecimal. So it supports 2^128 possible addresses (which is 340,282,366,920,938,000,000,000,000,000,000,000,000) (more than we'll ever need).

Even though IPv6 fixes IPv4 exhaustion, it has not been widely adopted.

![](/networking/networking-pics/IP-addresses-2.png)
> [Try Hack Me](https://tryhackme.com/room/whatisnetworking)

> [!Resources:]
> - [Try Hack Me: What is Networking](https://tryhackme.com/room/whatisnetworking)
> - [Subnetting Calculator](https://www.calculator.net/ip-subnet-calculator.html?cclass=any&csubnet=25&cip=65.190.192.225&ctype=ipv4&x=Calculate)
