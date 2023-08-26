
# CAN-2003-0201: trans2 Vulnerabilities
trans2 is a vulnerability in [SMB](/networking/protocols/SMB.md)v1 protocol which allows for a [buffer overflow](/cybersecurity/TTPs/exploitation/buffer-overflow.md). This is due to a string operation in the server code which copies a *client supplied string* to a *fixed-size* buffer *w/o checking to make sure the buffer can hold the entire string.*

Because the buffer happens *during a function call*, a buffer overflow is able to overwrite the instruction pointer copy which is saved on the stack. This vulnerability was first reported by Digital Defense Inc. in April of 2003 in advisory DDI-1013. Another associated vulnerability is *CAN-2003-0196* which is another buffer overflow in the Samba implementation of SMB (for Linux).
## Exploits
The most well known exploit of this vulnerability is a [Perl](/coding/languages/perl.md) script called *`trans2root.pl`*. This script, along w/ another called *`sambal.c`* are considered the original exploits because the other can all *trace their lineage back to them*. Between the two `sambal.c` has more features.
### `sambal.c`
`sambal.c` is able to *scan a large address space* for the existence of Samba servers. It differentiates them from Windows SMB servers via [application layer](/networking/OSI/application-layer.md) characteristics. This is in opposition to other common fingerprinting techniques like OS-fingerprinting.

It's also able to launch an attack via a *[connect-back](/cybersecurity/TTPs/persistence/connect-back.md) approach or [back-door](/cybersecurity/TTPs/persistence/back-door.md)* shell code.

> [!Resources]
> - [GIAC: Exploiting Samba's SMBTrans2 Vulnerability](https://www.giac.org/paper/gcih/484/exploiting-sambas-smbtrans2-vulnerability/105385)