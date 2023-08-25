
# SMB: Server Message Block
SMB is a server-client based architecture used on primarily Windows computers. It allows devices on the same network (and devices connected to the network remotely) to share files and printing services. Using SMB, files can be accessed, created, uploaded and downloaded, read and written to.

Ports 445 and 139 are reserved for SMB and uses [TCP](/networking/protocols/TCP.md) network protocol to “talk” to other computers over the internet/ network. Resources hosted on the SMB server are referred to as "shares" and are normally file directories.

Because Unix and Linux OS's can't use SMB, a similar, open-source protocol was developed in the 90s called "Samba".
## Security
The SMBv1 server used in some older versions of Windows has recently been exploited, most notably by [WannaCry](/cybersecurity/attacks/wannacry.md) and [NotPetya](/cybersecurity/attacks/notpetya.md). The [EternalBlue](/cybersecurity/vulnerabilities/eternalblue.md) vulnerability in SMBv1 allows an attacker to execute code on connected devices remotely.

> [!Resources]
> - [CyberSophia](https://cybersophia.net/articles/what-is/what-is-smb-protocol-and-why-is-it-a-security-concern/)
> - [SentinalOne Blog](https://www.sentinelone.com/blog/eternalblue-nsa-developed-exploit-just-wont-die/)

> [!Commands]
> - [`smbclient`](/CLI-tools/linux/smbclient.md)
> - `smbget`

> [!Ports]
> - port 445 
> - port 139
> 

 > [!Vulnerabilities] 
> - [EternalBlue](/cybersecurity/vulnerabilities/eternalblue.md)
> - [NotPetya](/cybersecurity/attacks/notpetya.md)

> [!Attacks] 
> - [WannaCry](/cybersecurity/attacks/wannacry.md)
