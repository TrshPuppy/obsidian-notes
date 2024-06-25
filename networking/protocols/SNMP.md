
# Simple Network Management Protocol
Protocol used in [application layer](../OSI/7-application/application-layer.md) for *querying [routers](../OSI/3-network/router.md) and [switches](../OSI/2-datalink/switches.md)*. Provides confidentiality by *encrypting data* as well as *authentication* and *integrity* (when using *SNMPv3*).
## Details
SNMP messages are transported using [UDP](UDP.md). An SNMP agent listens for requests on *`port 161`*. SNMP allows for the collection and organization of data on *managed devices* on a network. It also allows you to *modify the information* in order to change the behavior of these devices.

In more implementations, an administrative computer serves as the *'manager'* and monitors/ manages a group of hosts/ devices. The manager has software running on it called *Network Management Station*. Each managed device has an SNMP agent executing on it which reports info (using SNMP) back to the manager. 

Each host/ managed device has an SNMP interface which implements a *read only* access to information specific to that node.
![](../networking-pics/SNMP-1.png)
### Agent Software
The agent software (running on *managed devices*) has local knowledge of of management information and can translate it to or from SNMP.
### Network Mgmt Station Software
The NMS software (running on the *manager device*) executes applications which *monitor and control* the managed devices. It does the bulk of the processing and provides memory resources for managing the network. 

*One network can have multiple managers.*
## SNMPv3
Version 3 of SNMP doesn't change the protocol except to add *encryption* and *authentication.*. It also *looks* a lot different than previous versions because it adds new textual conventions, terminology and concepts. For example, SNMPv3 has *security and remote configuration enhancements*.

> [!Resources]
> - [Wikipedia: SNMP](https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol)
> - [`RFC 1157`](https://datatracker.ietf.org/doc/html/rfc1157)