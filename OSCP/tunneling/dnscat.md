---
aliases:
  - "`dnscat`"
---
# DNS Tunneling w/ `dnscat`
After understanding how to manually do [DNS-tunneling](../../cybersecurity/TTPs/c2/DNS-tunneling.md), we can now automate the process using a tool called [_dnscat2_](https://github.com/iagox86/dnscat2). `dnscat` allows us to *exfiltrate data* using [DNS](../../networking/DNS/DNS.md) queries, specifically [Subdomain](../../networking/DNS/DNS.md#Subdomain) queries. `dnscat` will also allow yo to *infiltrate* data using [`TXT` records](../../networking/DNS/TXT-record.md) (as well as other kinds of DNS records). 
## Basic Configuration




> [!Resources]
> - [_dnscat2_](https://github.com/iagox86/dnscat2)
