
# Network Time Protocol (NTP)
A network protocol which is used to *synchronize the time* of devices on a network. NTP is organized using a hierarchical structure.
## Hierarchy
The hierarchy is split into *"strata"*.
### Stratum 0
Highly accurate sources of timekeeping such as atomic clocks, GPS devices.
### Stratum 1
Stratum 1 devices are configured to *synchronize with stratum 0 devices*. These are called 'Stratum 1 servers'.
### Stratum 2
Stratum 2 servers synchronize according to stratum 1 servers, and so on...
## NTP Clients
In NTP, clients are devices on the network which can connect to NTP servers to configure their internal clock. NTP clients have to *query stratum servers* to get accurate time keeping data.
## Security
NTP is an important protocol as it relates to cybersecurity. Accurate time keeping is essential for many automated security tasks like *event logging*, authentication, cryptographic operations, network troubleshooting, and correlation of events on a device or network.

Unfortunately, NTP *has no security features.* Because of this, attackers can use it for *[DNS amplification](../../cybersecurity/TTPs/exploitation/DNS-amplification.md)* attacks.
### NTPSec (Secure NTP)
Began development in 2015. This upgrade focused on *fixing some vulns* and cleaning up the codebase of NTP.

> [!Resources]
> - [Professor Messer](https://www.youtube.com/watch?v=yuXK_Jyosus&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=101)