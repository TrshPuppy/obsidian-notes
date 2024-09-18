
# Dynamic Host Configuration Protocol
Init.
Networking protocol used to *automatically assign [IP addresses](../../PNPT/PEH/networking/IP-addresses.md)* from a pool of available addresses to devices which connect to the network. DHCP is useful because it takes away the need to *manually assign addresses* to every single device which connects.
## DHCP Exhaustion
Once the IP address pool is depleted of all available addresses, DHCP exhaustion occurs. There are no more addresses available to assign to new connecting devices. There are a few reasons this can happen:
- Network growth
- Misconfiguration
- Rogue or unauthorized devices
- Long Lease Duration
### DoS Starvation Attack
An attacker changes their *[MAC address](../../PNPT/PEH/networking/MAC-addresses.md)* so that they get assigned a new IP address, thus exhausting all the addresses in the DHCP pool.
## Security
DHCP *does not include built-in security.* So, controls outside the protocol are usually used to provide security. For example, in [active directory](../../computers/windows/active-directory/active-directory.md), DCHP servers *have to be authorized*. This is to avoid *rogue DHCP servers*. 

Another way security can be implemented for DHCP is to have [switches](../OSI/2-datalink/switches.md) be configured with *trusted interfaces*. This means that any DHCP IP address distribution is *only allowed from trusted interfaces*. This can be configured in Cisco switches, where it's referred to as *DHCP snooping*.

Another configuration which can be done on switches is to *limit the number of MAC addresses* per interfaces. For example, if an interface is attached to one device, we should *only see one MAC address* at that interface. This can be done to prevent DHCP exhaustion and *starvation attacks*.

> [!Resources]
> - [Professor Messer](https://www.youtube.com/watch?v=yuXK_Jyosus&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=101)