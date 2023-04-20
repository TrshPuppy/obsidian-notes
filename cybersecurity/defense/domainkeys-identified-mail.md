---
aliases: [domainkeys-identified-mail, DKIM]
---
# DomainKeys Identified Mail (DKIM)
Used to authenticate [email](/networking/email.md) which is being sent. #DKIM-record(s) exist in the #DNS and can survive forwarding (unlike #SPF).

## DKIM Record format:
```
v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxTQIC7vZAHHZ7WVv/5x/qH1RAgMQI+y6Xtsn73rWOgeBQjHKbmIEIlgrebyWWFCXjmzIP0NYJrGehenmPWK5bF/TRDstbM8uVQCUWpoRAHzuhIxPSYW6k/w2+HdCECF2gnGmmw1cT6nHjfCyKGsM0On0HDvxP8I5YQIIlzNigP32n1hVnQP+UuInj0wLIdOBIWkHdnFewzGK2+qjF2wmEjx+vqHDnxdUTay5DfTGaqgA9AKjgXNjLEbKlEWvy0tj7UzQRHd24a5+2x/R4Pc7PF/y6OxAwYBZnEPO0sJwio4uqL9CYZcvaHGCLOIMwQmNTPMKGC9nt3PSjujfHUBX3wIDAQAB
```

- `v=DKIM1`: The version of the record (optional)
- `k=rsa`: The key type
	- default = #RSA which is an #encryption algorithm
- `p=` The public key which will be matched to the private key created during the DKIM setup process

## DKIM Signatures:
In order to use DKIM #mail-servers attach #DKIM-signatures to emails they send.
- travels w/ the #email from source to destination
- mail servers en-route use the signatures to verify the email
	- verifies that the email actually came from the domain it claims to have come from 
- Each signature contains all the info needed for a server to verify that the signature is real and valid.
- The signature is encrypted by a pair of keys
	- the #private-key exists in the original, sending server
	- while the public key exists with the receiving server or ISP
	- the keys must match to verify the email's source

#### DKIM Selectors:
The #DKIM-selectors are specified in the DKIM-signature header and indicates where to locate the #public-key which matches the the private key in the sending server
- receiving server uses the DKIM selector to locate and retrieve the public key to match it against its copy of the private key, thus verifying the email is ==authentic and unaltered==

The DKIM-signature and selectors can be found in the "source code" or raw headers of the email:

![[Pasted image 20230218210338.png]]
-[dmarcian](https://dmarcian.com/dkim-selectors/)

In this image, the DKIM selector is indicated by the `s=` attribute (the selector is `s2048g1`)

>[!Tools]
> [DKIM Record Checker](>https://dmarcian.com/dkim-inspector/) (use to validate the correct configuration and syntax of a DKIM signature)

>[!links]
> [dmarcian](https://dmarcian.com/dkim-selectors/)

