
# Transport Layer Security
A cryptographic protocol used to secure data being sent over a network via encryption. TLS itself is made up of two layers:
- the TLS record
- the TLS handshake protocols
## Functions
TLS is used in multiple application types including [email](networking/email.md) and VOIP, but it's most publicly recognized for its use in [HTTPS](www/HTTPS.md). It's role is to provide privacy and confidentiality via encryption of data. It also provides *authentication* using [cryptography](computers/concepts/cryptography/cryptography.md) and digital certificates
### Certificates
TLS implements certificates to authenticate *the server* in client/server protocols like HTTPS. To authenticate the server, a third party has to sign *server-side digital certificates*.

A certificate guarantees that the holder is the *owner of a public key* which corresponds to a matching private key. The certificate also indicates the expected uses of that key. So, whatever actions are taken by others using the private key are considered trusted if they match the public key.
### Certificate Authorities
In order to verify the public/ private key pair of a web-service, TLS relies on a set of third-party authorities. These third parties are called 'certificate authorities' and they establish the authenticity of certificates.

> [!Resources]
> - [Wikipedia: TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_authorities)

