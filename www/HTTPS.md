
# Hypertext Transfer Protocol Secure
HTTPS is an extension of [HTTP](www/HTTP.md). While HTTP facilitates *unencrypted* data transfer b/w a client and webserver, HTTPS encrypts data as well as *authenticates* the website being accessed.
## Security
HTTPS uses [TLS](networking/protocols/TLS.md) (Transport Layer Security) to encrypt data and authenticate the server involved in an HTTPS relationship. The job of TLS is not only to encrypt the data, but also verify the *certificate held by the server*. This certificate is only considered reliable if it's been verified by a *third-party certificate authority.*
### Encryption
The data exchanged b/w a client and server over HTTPS is *encrypted by a session key*. The session key is generated using the *public and private keys* created for the server and authenticated using TLS and certificate authorities.

While the session key is short term, the public and private keys are considered *long term*. In order for this to work *the entire site has to be hosted using HTTPS*. That's because every time the site is accessed over HTTP the *user and session are exposed*.
### Certification
When a browser visits a website (and queries the webserver for its contents), the browser knows it can trust an `https://` website based on the *certificate authorities it has pre-installed in its software*. This means that the certificate authority the web browser is trusting needs to *actually be a legitimate authority*. In order for an HTTPS connection to *actually* be trustworthy, a few things have to be true:
- The device hosting the browser and the method used to get to the browser is not compromised
- The browser software *correctly* implements HTTPS w/ pre-installed cert. authorities.
- The certificate authority itself is *only* vouching for legitimate, trustworthy sites.
- The website provides a valid certificate.
- The certificate identifies the correct website.
- The encryption layer (usually SLS/TLS) is properly secured against eavesdropping.

> [!Resources]
> - [Wikipedia: TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_authorities)
> - [Wikipedia: HTTPS](https://en.wikipedia.org/wiki/HTTPS#Security)
