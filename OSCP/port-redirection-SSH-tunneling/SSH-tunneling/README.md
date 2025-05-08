---
aliases:
  - SSH Tunneling
---
# SSH Tunneling
Tunneling is the act of *encapsulating* one kind of data stream in another.  Protocols which support tunneling are called *tunneling protocols* and [SSH](../../../networking/protocols/SSH.md) is one of those. SSH was originally designed to provide server login capabilities over an encrypted connection which improved on older protocols like [telnet](../../../networking/protocols/telnet.md). 

SSH was designed *primarily as a tunneling protocol* meaning almost *any kind* of data can pass through an SSH connection. Because of its versatility, it's common to find SSH client services running on organizations' networks. Because it's so prevalent, it *blends into normal traffic* and, unless the network is heavily monitored, SSH traffic is unlikely to be seen as anomalous or malicious. 

Another advantage for using SSH tunneling during a pen-test is the contents of the traffic *cannot be monitored easily*. 

> [!Resources]
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.