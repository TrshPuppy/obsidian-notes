
# DNS lookup utility
Used to manually query *recursive [DNS](/networking/DNS/DNS.md) servers* for info about domains.
## Usage 
```
dig  [@server] [-b address] [-c class] [-f filename] [-k filename] [-m]
       [-p port#] [-q name] [-t type] [-v] [-x addr]  [-y  [hmac:]name:key]  [
       [-4] | [-6] ] [name] [type] [class] [queryopt...]
```  
### Querying a Specific Server
```
dig <domain> @<dns-server-ip>
```
Example:
![](/CLI-tools/CLI-tools-pics/dig-1.png) 
> [TryHackMe](https://tryhackme.com/room/dnsindetail)
### `ANSWER` section: 
Contains the IP address you're looking for.
### `TTL` (Time to Live)
When your computer queries a domain name, it stores the result in local cache. The TTL tells your computer *when to stop considering the record as valid* (when it should request the data again).
![](/CLI-tools/CLI-tools-pics/dig-2.png)
The TTL is measured in seconds. So for this example, the record expires in 2 minutes and 30 seconds
## Usage Examples
### `+short`
Giving the `+short` flag will shorten dig's output:
```bash
└─# dig +short ns1.megacorpone.com
51.79.37.18
```
### Reverse lookups
The `-x` option will tell dig to do a reverse DNS lookup of the provided IP address. Dig will treat this as if you're querying for the [PTR record](../networking/DNS/PTR-record.md) of the specified IP address.
```bash
└─# dig -x 51.79.37.18

; <<>> DiG 9.19.19-1-Debian <<>> -x 51.79.37.18
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 59402
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;18.37.79.51.in-addr.arpa.	IN	PTR

;; ANSWER SECTION:
18.37.79.51.in-addr.arpa. 300	IN	PTR	ns1.megacorpone.com.

;; Query time: 16 msec
;; SERVER: 172.31.0.2#53(172.31.0.2) (UDP)
;; WHEN: Thu Jan 23 20:47:02 EST 2025
;; MSG SIZE  rcvd: 86
```

> [!Resources]
> - `man dig`
> - [TryHackMe: DNS in Detail](https://tryhackme.com/room/dnsindetail)
