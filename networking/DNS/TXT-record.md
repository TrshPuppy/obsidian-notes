---
aliases:
  - TXT
  - TXT record
  - "`TXT`"
  - "`TXT` record"
  - "`TXT` records"
---
INIT
# DNS TXT Record
TXT records are a type of [DNS](DNS.md) record. They're usually used by domain admins to enter arbitrary text into the DNS system and are stored in the form of *strings with quotation marks*. TXT records were originally intended to store human readable data and notes. However, TXT records can store any type of data as long as it's in a "text string" format (per the [original RFC](https://tools.ietf.org/html/rfc1035)) and is shorter than *256 bytes*. 
## Use
TXT records on a domain are usually used for [email](../email.md) spam prevention and *domain verification*.


> [!Resources]
> - [Cloudflare: TXT Records](https://www.cloudflare.com/learning/dns/dns-records/dns-txt-record/)
> - [original RFC](https://tools.ietf.org/html/rfc1035)

> [!Related]
> - [DNS tunneling](../../OSCP/tunneling/DNS-tunneling.md)l