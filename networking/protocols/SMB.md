
# SMB: Server Message Block
SMB is an [application-layer](/networking/OSI/application-layer.md) server-client based architecture used on primarily Windows computers. It is a File Sharing Protocol which allows devices on the same network (and devices connected to the network remotely) to share files and printing services. Using SMB, files can be accessed, created, uploaded and downloaded, read and written to.

*Ports 445 and 139* are reserved for SMB and use the [TCP](/networking/protocols/TCP.md) network protocol to “talk” to other computers over the internet/ network. In order for two devices/client to use SMB, they have to *connect to a supporting server using [NetBIOS](/networking/protocols/NetBIOS.md)* over TCP/IP (also referred to as *NBT*). Resources hosted on the SMB server are referred to as "shares" and are normally file directories.
## Samba
Because Unix and Linux OS's can't use SMB, a similar, open-source protocol was developed in the 90s called "Samba". Samba is a software implementation of SMB and also makes use of NetBIOS. With Samba, a Unix-OS computer can share files/ shares/ printers with Windows devices.

Because Samba also uses NetBIOS/ NBT, it also runs NetBIOS's Session Service over TCP `port 139`.
## Security
SMB has two levels of security; the *share level*, and *user level* which was added in later version.
### Share level:
Each share has a password which the client needs to enter in order to access it. This helps protect the server. This layer is 'available in the *Core and Core plus SMG* protocol definitions'(Hacking Articles).
### User Level:
User level protection is applied to each share and individual files. When the client is authenticated by the server, they receive *a unique ID (UID)* which is *presented to the server upon access.* This security mechanism has been present since LAN Manager 1.0.
## Exploits/ CVEs:
### SMBv1
The *SMBv1* server used in some older versions of Windows has recently been exploited, most notably by [WannaCry](/cybersecurity/attacks/wannacry.md) and [NotPetya](/cybersecurity/attacks/notpetya.md). The [EternalBlue](/cybersecurity/vulnerabilities/eternalblue.md) vulnerability in SMBv1 allows an attacker to execute code on connected devices remotely.
### Samba
#### trans2
When dealing w/ *Samba* the [trans2](/cybersecurity/vulnerabilities/trans2.md) vulnerability allows for a [buffer overflow](/cybersecurity/TTPs/exploitation/binary-exploitation/buffer-overflow.md). This is due to a string operation in the code with copies a *client supplied string* to a *fixed-size* buffer *w/o checking to make sure the buffer can hold the entire string.*

Because the buffer happens *during a function call*, a buffer overflow is able to overwrite the instruction pointer copy which is saved on the stack.

> [!Resources]
> - [CyberSophia](https://cybersophia.net/articles/what-is/what-is-smb-protocol-and-why-is-it-a-security-concern/)
> - [SentinalOne Blog](https://www.sentinelone.com/blog/eternalblue-nsa-developed-exploit-just-wont-die/)
> - [GIAC: Exploiting Samba's SMBTrans2 Vulnerability](https://www.giac.org/paper/gcih/484/exploiting-sambas-smbtrans2-vulnerability/105385)

> [!Related]
> - Commands: [`smbclient`](/CLI-tools/linux/smbclient.md), `smbget`
> - Tools: [`enum4linux`](/cybersecurity/tools/scanning-enumeration/enum4linux.md)
> - Ports: `port 445`, `port 139`
> - Vulnerabilities: [EternalBlue](/cybersecurity/vulnerabilities/eternalblue.md), [NotPetya](/cybersecurity/attacks/notpetya.md), [trans2](/cybersecurity/vulnerabilities/trans2.md)
> - Attacks: [WannaCry](/cybersecurity/attacks/wannacry.md), [SMB-relay](/PNPT/PEH/active-directory/initial-vectors/SMB-relay.md)
> - Enumeration: [Enumerating SMB](/PNPT/PEH/scanning-enumeration/enumerating-SMB.md)
