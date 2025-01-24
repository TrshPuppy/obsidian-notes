
# DNS PTR Record
The PTR or 'pointer' record is the *opposite* of an [A Record](A-record.md) on a domain. While an A record holds the [IP address](../OSI/3-network/IP-addresses.md) that a domain resolves to, a PTR record holds the *domain name that an IP address resolves to*.

Querying for a PTR record is called a *DNS Reverse Lookup*.
## Storage
Since PTR records are not meant for domain names *they are not stored under a given domain*. Instead, they are stored w/i the *`.apra` [Top Level Domain](DNS.md#Top%20Level%20Domain)* in the DNS system. `.arpa` domains are used for *managing network infrastructure* and is actually the *first TLD* defined for the internet. The name 'ARPA' stands for 'Advanced Research Projects Agency' which created [ARPANET](../ARPANET.md) - the original precursor to the internet.
### Format
PTR records in the `.arpa` domain are saved in the `in-addr.arpa` namespace. So, each PTR record is stored under a specific name, which is the IP address they're associated with reversed and appended to the namespace. 
#### Example
The PTR record for the IP address `192.0.2.255` would be named:
```bash
255.2.0.192.in-addr.arpa
```
If the domain hosted on this IP address is `example.domain.xyz`, then `255.2.0.192.in-addr.arpa` (the PTR record) will hold that information. 

> [!Resources]
> - [Cloudflare: PTR Records](https://www.cloudflare.com/learning/dns/dns-records/dns-ptr-record/)