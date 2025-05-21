---
aliases:
  - DKIM
  - domain keys identified mail
---
# DomainKeys Identified Mail
DKIM is sed to authenticate [email](/networking/email.md) which is being sent. DKIM record exist in the [DNS](../../networking/DNS/DNS.md) (usually as a [`TXT` record](../../networking/DNS/TXT-record.md) on a domain) and can survive forwarding (unlike [SPF](SPF.md)).
## DKIM Record format
```
v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxTQIC7vZAHHZ7WVv/5x/qH1RAgMQI+y6Xtsn73rWOgeBQjHKbmIEIlgrebyWWFCXjmzIP0NYJrGehenmPWK5bF/TRDstbM8uVQCUWpoRAHzuhIxPSYW6k/w2+HdCECF2gnGmmw1cT6nHjfCyKGsM0On0HDvxP8I5YQIIlzNigP32n1hVnQP+UuInj0wLIdOBIWkHdnFewzGK2+qjF2wmEjx+vqHDnxdUTay5DfTGaqgA9AKjgXNjLEbKlEWvy0tj7UzQRHd24a5+2x/R4Pc7PF/y6OxAwYBZnEPO0sJwio4uqL9CYZcvaHGCLOIMwQmNTPMKGC9nt3PSjujfHUBX3wIDAQAB
```
- `v=DKIM1`: The version of the record (optional)
- `k=rsa`: The key type (default = [RSA](../../computers/concepts/cryptography/RSA.md) which is an [encryption](../../OSCP/password-attacks/README.md) algorithm)
- `p=` The public key which will be matched to the private key created during the DKIM setup process
## DKIM Signatures
In order to use DKIM, email servers attach DKIM signatures to emails they send. The signature travels w/ the from source to destination. Mail servers the email traverses en route to the destination- mail *use the signatures to verify the email*.

The signature itself is used to verify that the email actually came from the domain it claims to have come from.  Each signature contains all the info needed for a server to verify that the signature is real and valid.
### Creation
The signature is encrypted by a pair of keys. The private key exists in the original, sending server while the public key exists with the receiving server or ISP. The keys must correlate to verify the email's source.
### DKIM Selectors
The DKIM selectors are specified in the*DKIM-Signature header* and indicates where to locate the public key which correlates to the private key in the sending server

The *receiving server* uses the DKIM selector to locate and retrieve the public key to match it against its copy of the private key, thus verifying the email is *authentic and unaltered*.

The DKIM-signature and selectors can be found in the "source code" or raw headers of the email:
![](/cybersecurity/cybersecurity-pics/DKIM-1.png)
-[dmarcian](https://dmarcian.com/dkim-selectors/)

In this image, the DKIM selector is indicated by the `s=` attribute (the selector is `s2048g1`)

>[!Resources]
> - [DKIM Record Checker](>https://dmarcian.com/dkim-inspector/) (use to validate the correct configuration and syntax of a DKIM signature)
> - [dmarcian](https://dmarcian.com/dkim-selectors/)


