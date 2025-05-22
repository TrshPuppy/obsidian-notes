---
aliases:
  - dynamic port forwarding
  - SOCKS
  - SSH dynamic port forwarding
  - dynamic port forward
---
# SSH Dynamic Port Forwarding
[Local port forwarding](local-port-forwarding.md) has an important *limitation*: you can only use *one socket per [SSH](../../../networking/protocols/SSH.md) connection*, which makes it difficult to use at scale. Fortunately, Open SSH also provides *Dynamic port forwarding* from a single listening port *on the SSH client*. 

With Dynamic forwarding, packets can be forwarded *to any address the SSH server has access to*. That's because the SSH client's listening port acts as a [_SOCKS_](https://en.wikipedia.org/wiki/SOCKS) proxy server port. SOCKS is a *[proxy](../../../networking/design-structure/proxy.md)ing* protocol. It accepts packets and (if they have a SOCKS header) forwards them to wherever they're addressed-- similar to a postal service:
![](../../oscp-pics/dynamic-port-forwarding-1.png)
The biggest limitation to dynamic port forwarding through SOCKS is that the packets *have to be properly formatted*. This means that you need access to SOCK-compatible software on the client.
## Scenario
Assume the same scenario as in the [local-port-forwarding](local-port-forwarding.md) notes, but this time, instead of just connecting to the [SMB](../../../networking/protocols/SMB.md) service on `HRSHARES`, we also want to do a full [port scan](../../enum-and-info-gathering/active/port-scanning.md). First, we can spawn a [TTY](../../../computers/linux/terminal-tty-shell.md) using python:
```bash
confluence@confluence01:/opt/atlassian/confluence/bin$ python3 -c 'import pty; pty.spawn("/bin/sh")'
</bin$ python3 -c 'import pty; pty.spawn("/bin/sh")'
```
### `ssh -D`
Once we're in the new bash TTY, then we can use `ssh` with the `-D` flag to setup a *dynamic port forward*, giving it the IP address and port we want to bind to. Based on our diagram, we want to open port `9999` on `CONFLUENCE01` and configure it to listen *on all interfaces* (`0.0.0.0`). Unlike the local port forwarding command, *we don't have to give it the address to forward traffic to*. Don't forget `-N` to prevent a shell from being spawned upon connection:
```bash
$ ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215
<$ ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215   
Could not create directory '/home/confluence/.ssh'.
The authenticity of host '10.4.50.215 (10.4.50.215)' can't be established.
ECDSA key fingerprint is SHA256:K9x2nuKxQIb/YJtyN/YmDBVQ8Kyky7tEqieIyt1ytH4.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
yes
Failed to add the host to the list of known hosts (/home/confluence/.ssh/known_hosts).
database_admin@10.4.50.215's password:
```
### Connecting Thru the SOCKS Proxy
Now that our SOCKS proxy connection is setup, we can connect to it from our Kali machine. We can start by connecting to the `HRSHARES` SMB service (port `445`) but instead of using [smbclient](../../../CLI-tools/linux/remote/smbclient.md) like we did last time, we'll have to use something else. This is because `smbclient` *doesn't support SOCKS connections*.

If we try to use smbclient, it wouldn't know *how to handle traffic encapsulated with the SOCKS protocol* format. However, we **CAN** use `smbclient` if we leverage [_Proxychains_](https://github.com/rofl0r/proxychains-ng). 
#### Proxychains
Proxychains is a tool usually used to send traffic *over a concurrent chain of [proxies](../../../networking/design-structure/proxy.md)* (and can be used to circumvent censorship in whack-ass countries like N.K.!). But it can also be used to force network traffic from tools like `smbclient` over [HTTP](../../../www/HTTP.md) or SOCKS.

The tool itself actually makes use of a little hack. It uses [Linux](../../../computers/linux/README.md) "shared object preloading" to hook `libc` networking functions which get passed to it. It then forces all connections over a configured proxy server. Because of this *it might not work for everything*, but should for most dynamically linked binaries doing simple network operations.
##### Configuring Proxychains
To use `smbclient ` with proxychains, we need to edit the Proxychains configuration file at `/ect/proxychains4.conf` so it can locate and confirm our SOCKS proxy port. Proxies need to be defined *at the end of the conf file* using a single line to define:
- the proxy type
- IP address
- port

The end of the file should look like this after we edit it:
```bash
tail /etc/proxychains4.conf
#       proxy types: http, socks4, socks5, raw
#         * raw: The traffic is simply forwarded to the proxy without modification.
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 192.168.50.63 9999
```
### Using `smbclient`
Now that proxychains is setup, we can use `smbclient` to list the shares on `HRSHARES`. All we have to do is *prepend `proxychains` to the command*. This will tell proxychains to *hook into the `smbclient` process* and force all the traffic thru the SOCKS proxy (we specified in the PC conf file):
```bash
proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  192.168.50.63:9999  ...  172.16.50.217:445  ...  OK

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
    scripts         Disk
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
[proxychains] Strict chain  ...  192.168.50.63:9999  ...  172.16.50.217:139  ...  OK
[proxychains] Strict chain  ...  192.168.50.63:9999  ...  172.16.50.217:139  ...  OK
do_connect: Connection to 172.16.50.217 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
Along with our `smbclient` output, proxychains also listed the ports it interacted with while facilitating the `smbclient` connection.
### Port Scanning Through Proxychains SOCKS Proxy
We know now that our proxychains SOCKS proxy connection is working. Now we can try port scanning `HRSHARES` with [nmap](../../../CLI-tools/linux/remote/nmap.md). We'll do a [TCP](../../../networking/protocols/TCP.md) connect scan and skip DNS resolution and host discovery. We'll also just scan the *top 20 most common ports*:
```bash
proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-20 17:26 EDT
Initiating Parallel DNS resolution of 1 host. at 17:26
Completed Parallel DNS resolution of 1 host. at 17:26, 0.09s elapsed
DNS resolution of 1 IPs took 0.10s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 17:26
Scanning 172.16.50.217 [20 ports]
[proxychains] Strict chain  ...  192.168.50.63:9999  ...  172.16.50.217:111 <--socket error or timeout!
[proxychains] Strict chain  ...  192.168.50.63:9999  ...  172.16.50.217:22 <--socket error or timeout!
...
[proxychains] Strict chain  ...  192.168.50.63:9999  ...  172.16.50.217:5900 <--socket error or timeout!
Completed Connect Scan at 17:30, 244.33s elapsed (20 total ports)
Nmap scan report for 172.16.50.217
Host is up, received user-set (9.0s latency).
Scanned at 2022-08-20 17:26:47 EDT for 244s

PORT     STATE  SERVICE       REASON
21/tcp   closed ftp           conn-refused
22/tcp   closed ssh           conn-refused
23/tcp   closed telnet        conn-refused
25/tcp   closed smtp          conn-refused
53/tcp   closed domain        conn-refused
80/tcp   closed http          conn-refused
110/tcp  closed pop3          conn-refused
111/tcp  closed rpcbind       conn-refused
135/tcp  open   msrpc         syn-ack
139/tcp  open   netbios-ssn   syn-ack
143/tcp  closed imap          conn-refused
443/tcp  closed https         conn-refused
445/tcp  open   microsoft-ds  syn-ack
993/tcp  closed imaps         conn-refused
995/tcp  closed pop3s         conn-refused
1723/tcp closed pptp          conn-refused
3306/tcp closed mysql         conn-refused
3389/tcp open   ms-wbt-server syn-ack
5900/tcp closed vnc           conn-refused
8080/tcp closed http-proxy    conn-refused

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 244.62 seconds
```
The scan appears to be successful! We can see that, along with [SMB](../../../networking/protocols/SMB.md) on port `445`, the `HRSHARES` host on the internal network also has ports `135`, `139`, `3389` open.
> [!Note]
> Proxychains is configured by default to have *really high time-out values* which can make port scanning take a much longer time. Lower timeout times by changing the `tcp_read_time_out` and `tcp_connect_time_out` values in the PrCh configuration file. This will force PrCh to time out on *non-responsive connections* more quickly.

> [!Resources]
> - [_SOCKS_](https://en.wikipedia.org/wiki/SOCKS)
> - [_Proxychains_](https://github.com/rofl0r/proxychains-ng)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.