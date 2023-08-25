
# EternalBlue Family (CVE-2017-0143 thru -0148)
A family of "critical" vulnerabilities in Microsoft [SMB](/networking/protocols/SMB.md)v1 servers and server protocol. These vulnerabilities not only effect Windows machines, but also machines which make use of the same server protocol including Siemens ultrasound medical equipment.

## CVE-2017-0144 (EternalBlue itself):
A flaw in the SMBv1 server allows remote adversaries to execute code on a target computer. An unauthenticated attacker can craft malicious packets and send them to the server. Because SMB allows devices on a network to share resources w/ each other, malware like [WannaCry](/cybersecurity/attacks/wannacry.md) can use the server to propagate to other devices.

This technique is rumored to have been developed by the NSA and/or an APT group known as the "Equation Group". 

### Pathophysiology:
SMB allows for meta-data about a shared file to be communicated along with the file. This meta-data is called "extended attributes" and includes information about the file's properties related to the filesystem.

#### Buffer Overflow:
When the protocol attempts to determine how much memory needs to be allocated (for an incoming packet) a mathematical error creates an integer overflow which in turn causes less memory to be allocated than expected. 

Because there isn't enough space allocated for the incoming data, the data spills over into *adjacent memory space*.

#### Malicious Packets:
A buffer overflow can be achieved by crafting a packet which takes advantage of two sub commands in the protocol; `SMB_COM_TRANSACTION2` and `SMB_CON_NT_TRANSACT`. Both of these sub commands have the `_SECONDARY` command which is used when there is too much data to fit into one packet.

An attacker (sending a packet to the server as the client) can craft a packet which uses the `SMB_CON_NT_TRANSACT` sub command *before* the `SMB_CON_TRANSACTION2` sub command. Despite recognizing that two separate commands have been sent, the server will allocate memory for *both packets* based only on *the type of the last packet received*.

Because the `SMB_CON_TRANSACTION2` requires half the size of memory to be allocated when compared to `SMB_CON_NT_TRANSACT`, the first packet will overflow into memory not allocated for it because only half the space it requires has been allocated for it.

#### [Heap Spraying:](/cybersecurity/TTPs/heap-spraying.md)
Once the second packet has achieved an overflow, the attacker can take advantage of a third bug in the SMB protocol which allows "heap spraying". 

Heap Spraying allows the attacker to inject shellcode into parts of the memory which are pre-determined, and which the computer is likely to read. Any code injected into the memory can be used to take control of the entire system.

## Mitigation:
The most effective way to mitigate against EternalBlue is to update older versions of Windows and make sure the Ms17-10 security patch is applied. 

Other ways to mitigate include disabling SMBv1 and not exposing vulnerable systems to the internet.

> [!Resources:]
> [SentinelOne: EternalBlue Exploit](https://www.sentinelone.com/blog/eternalblue-nsa-developed-exploit-just-wont-die/)






