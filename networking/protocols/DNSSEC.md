
# DNSSEC (DNS Security Extensions)
A protocol used in [DNS](networking/DNS/DNS.md) to mitigate against [DNS-based attacks](networking/DNS/DNS-security.md). The main function of DNSSEC is to *digitally sign data* in order to validate it. Signing must occur *at every level* of a DNS lookup for the data to be properly validated.

This provides *authentication* and *data integrity*.
## Parent-Child Trust
DNSSEC uses a parent-child chain of trust. When a hostname lookup is done, let's say for `trashpuppy.com`, the root DNS server signs a key for the `.com` nameserver, which signs a key for the authoritative nameserver for `trashpuppy.com`.
### [Public Key Cryptography](../../computers/concepts/cryptography/asymmetric-encryption.md)
The chain starts with the root server which has to be validated. For the root server, *validation is done during a human ceremony* in what is called the *"Root Zone Signing Ceremony"*. During this ceremony individuals from around the world are selected to meet. They then verify that the root zone hasn't been tampered with and is free of fraud. They then sign the root `DNSKEY RRset`  publicly and in an audited way.

If the chain is compromised at any level along the resolution path, the request becomes vulnerable to an *on-path attack*.
## Integration
DNSSEC was designed to be *backwards compatible* so that traditional DNS lookups still resolve correctly. However, they don't benefit from the added security of signing.

Additionally, DNSSEC can be integrated w/ other security measures including [TLS](networking/protocols/TLS.md)/SLS.

> [!Resources]
> - [Cloudflare: DNS Security](https://www.cloudflare.com/learning/dns/dns-security/)
> - [Professor Messer](https://www.youtube.com/watch?v=yuXK_Jyosus&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=101)

