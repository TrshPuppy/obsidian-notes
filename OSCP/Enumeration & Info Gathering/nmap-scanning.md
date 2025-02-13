
# Port Scanning with Nmap
[Nmap](../../CLI-tools/linux/remote/nmap.md) is the most popular port scanning tool. It's written by Gordon Lyon/ Fyodor and has been in active development for 2 decades. One thing that makes nmap the best is that it deals in *raw sockets* which require root privilege to access (so some scans have to be run using `sudo`). Raw sockets allow you to *manipulate the network packets*, whereas scanning with a regular socket means you have to follow the [Berkeley socket API](https://networkprogrammingnotes.blogspot.com/p/berkeley-sockets.html) standards.
## Footprint
It's important to understand the mark you leave on a scanned host when you do port scanning. In a standard TCP scan, we scan the top 1000 [ports](../../networking/routing/ports.md) because *they are the most used* (and are designated). Technically, the first 1023 are assigned to specific protocols and services, the rest are dynamic or "ephemeral" (meaning they can be temporarily assigned to any application). The first 1023 have to follow a *set of standards*.

To see how much traffic is received by the remote host by this type of scan, we'll use the `iptables` command (on the target host).
### `iptables` 
[`iptables`](https://netfilter.org/projects/iptables/index.html) is a Linux command used to configure network *packet filtering* rulesets. You can use it to create filters, then list the contents of those filters, modify the rules of the filter, etc.. Our iptables command looks like this:
```bash
┌──(trshpuppy㉿kali)-[~/oscp/recon]
└─$ sudo iptables -I INPUT 1 -s 192.168.157.151 -j ACCEPT
[sudo] password for trshpuppy:

┌──(trshpuppy㉿kali)-[~/oscp/recon]
└─$ sudo iptables -I OUTPUT 1 -d 192.168.157.151 -j ACCEPT

┌──(trshpuppy㉿kali)-[~/oscp/recon]
└─$ sudo iptables -Z
```
- `-I`: This tells [iptables](../../CLI-tools/linux/local/iptables.md) to insert a new rule into a specific "chain", the chain in this case is the `INPUT` (inbound) chain and the `OUTPUT` (outbound) chain. `-I` is followed by the *rule number* (which is `1`)
- `-s`: specifies the source IP address
- `-d`: specifies the destination IP address
- `-j`: tells iptables to `ACCEPT` traffic
- `-Z`: tells iptables to zero the packet and byte count in all chains 
#### Nmap command
Now that we've created some filter rules, we'll run the following nmap scan:
```bash
┌──(trshpuppy㉿kali)-[~/oscp/recon]
└─$ nmap 192.168.157.151
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-13 10:32 EST
Nmap scan report for 192.168.157.151
Host is up (0.10s latency).
Not shown: 985 closed tcp ports (conn-refused)
PORT     STATE    SERVICE
53/tcp   open     domain
88/tcp   open     kerberos-sec
135/tcp  open     msrpc
139/tcp  open     netbios-ssn
389/tcp  open     ldap
445/tcp  open     microsoft-ds
464/tcp  open     kpasswd5
512/tcp  filtered exec
593/tcp  open     http-rpc-epmap
636/tcp  open     ldapssl
3128/tcp filtered squid-http
3268/tcp open     globalcatLDAP
3269/tcp open     globalcatLDAPssl
3809/tcp filtered apocd
4129/tcp filtered nuauth

Nmap done: 1 IP address (1 host up) scanned in 16.61 seconds
```
#### Reviewing the `iptables` filter
Now that our scan is complete, let's look at our filter using iptables (which will give us statistics on the traffic we generated).
```bash
┌──(trshpuppy㉿kali)-[~/oscp/recon]
└─$ sudo iptables -vn -L
Chain INPUT (policy ACCEPT 1176 packets, 112K bytes)
 pkts bytes target     prot opt in     out     source               destination
 1100 44792 ACCEPT     all  --  *      *       192.168.157.151      0.0.0.0/0

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy ACCEPT 1244 packets, 140K bytes)
 pkts bytes target     prot opt in     out     source               destination
 1235 74836 ACCEPT     all  --  *      *       0.0.0.0/0            192.168.157.151
    0     0 ACCEPT     all  --  *      *       192.168.157.151      0.0.0.0/0
```
- `-v`: verbosity
- `-n`:  create a new chain
- `-L`:  list the rules in the chain/ chains
In our `OUTPUT` chain, we can see that the outgoing traffic to the target host is 74,836 bytes, or 74KB of data! If we use `-Z` to *zero* the packet and byte counters again, we can run a full nmap scan of all 65k+ ports and see how much traffic we send to the target as comparison:
```bash
┌──(trshpuppy㉿kali)-[~/oscp/recon]
└─$ sudo iptables -vn -L nmap -p 1-65535 192.168.157.151
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-09 05:23 EST
Nmap scan report for 192.168.157.151
Host is up (0.11s latency).
Not shown: 65510 closed tcp ports (conn-refused)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
...

Nmap done: 1 IP address (1 host up) scanned in 2141.22 seconds

┌──(trshpuppy㉿kali)-[~/oscp/recon]
└─$ sudo iptables -vn -L
Chain INPUT (policy ACCEPT 67996 packets, 6253K bytes)
 pkts bytes target     prot opt in     out     source               destination
68724 2749K ACCEPT     all  --  *      *       192.168.157.151      0.0.0.0/0

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy ACCEPT 67923 packets, 7606K bytes)
 pkts bytes target     prot opt in     out     source               destination
68807 4127K ACCEPT     all  --  *      *       0.0.0.0/0            192.168.157.151
```
This is a local port scan which probes all 65,535 ports on the target host, and it generated about *4MB* or traffic - much higher than the sub 1000 scan. 

If we were to do a full nmap TCP scan of a *[Class C](../../networking/routing/CIDR.md#Class%20C) network* (254 hosts), we would be sending over 1000MB of traffic to that network. While this would provide the most accurate information, it would take way too long and send too much traffic to the target.

You might be wondering about other tools like [masscan](../../cybersecurity/TTPs/recon/tools/scanning/masscan.md) and RustScan for these situations. While these tools are faster than Nmap they *generate much more traffic* which is *[concurrent](../../coding/concepts/coroutines.md#Concurrency)* (lots of packets sent at the same time to the target).
## Nmap scanning techniques


> [!Resources]
> - [Berkeley socket API](https://networkprogrammingnotes.blogspot.com/p/berkeley-sockets.html)
> - [`iptables`](https://netfilter.org/projects/iptables/index.html) 
