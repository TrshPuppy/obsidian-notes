# SSH Command
Command line tool to connect to devices via the [SSH](/networking/protocols/ssh) protocol.
## Usage:
To connect to a device via #ssh you need the IP of the target and the correct credentials:
```shell
# syntax: username@IP.Address
ssh tryhackme@10.10.194.63
The authenticity of host '10.10.194.63 (10.10.194.63)' can't be established.
ECDSA key fingerprint is SHA256:<key fingerprint>.
Are you sure you want to continue connecting (yes/no)? y
Please type 'yes' or 'no': yes
Warning: Permanently added '10.10.194.63' (ECDSA) to the list of known hosts.
tryhackme@10.10.194.63's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-1047-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Apr  7 18:17:24 UTC 2023

  System load:  0.0               Processes:             108
  Usage of /:   26.8% of 7.69GB   Users logged in:       0
  Memory usage: 23%               IPv4 address for eth0: 10.10.194.63
  Swap usage:   0%

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

tryhackme@linux2:~$ 
```
### Config Example
```
Host <custom host name>
	Hostname <IP>
	User Administrator
	IdentityFile .ssh\SSH-Private.pem

Host <custom host name>
        HostName <IP>
        User root
        IdentityFile .ssh\SSH-Private.pem
        ProxyJump natfuel_windows
```
### SOCKS Proxy
```bash
ssh -D 44444 <user>@<IP address>
```
This creates a SOCKS server which you can connect to to create a SOCKS connection. For example, if I want to proxy all of my [burp-suite](../cybersecurity/TTPs/delivery/tools/burp-suite.md) traffic through a [proxy](../networking/design-structure/proxy.md) so it is sent from the IP address `1.2.3.4`, then the SSH command on my local machine would be:
```bash
ssh -D 44444 root@1.2.3.4
```
And the address of the SOCKS proxy host I give to Burp would be `127.0.0.1:44444` or (expanded): `socks5://127.0.0.1:44444`.

> [!Resources]
> - `man ssh`
> - [Question about SOCKS proxy on Stack Exchange](https://superuser.com/questions/1308495/how-to-create-a-socks-proxy-with-ssh)