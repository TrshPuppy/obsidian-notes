---
aliases:
  - "`CNAME` records"
  - "`CNAME` record"
---
# Canonical Name Record (CNAME)
The CNAME record points an alias domain name *to a 'canonical' domain.* It's used instead of an [A record](/networking/DNS/A-record.md) *when a domain or subdomain **is an alias** for another domain*.

Unlike A records, CNAME Records *must point to a domain* and never to an [IP address](/networking/OSI/3-network/IP-addresses.md). A domain w/ a CNAME can point to another domain w/ a CNAME (another alias) OR to a domain w/ an A record.
## Example:
If we have `blog.example.com` which has a *CNAME record* pointing to `example.com`, then, when the [DNS](/networking/DNS/DNS.md) server finds the record for `blog.example.com`, it will trigger a *second DNS lookup* for `example.com`.

The request will finally resolve *with the IP address for `example.com`*. This means that `example.com` is the canonical name (the true name) for `blog.example.com`.
## Subdomains
CNAME records are used a lot in sites which have subdomains. For a root domain like `example.com`, all the subdomains (`blog.example.com`, `shop.example.com`, etc.) can be given a CNAME record which points to `example.com`.

This is useful because if the IP address of `example.com` changes, then only its A record needs to be updated, and all the CNAME records of the subdomains will follow along.

> [!Resources]
> - [Cloudflare: DNS CNAME Record](https://www.cloudflare.com/learning/dns/dns-records/dns-cname-record/)

