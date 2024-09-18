
# WHOIS
A [TCP](../protocols/TCP.md)-based query and response protocol which is used to provide information related to registered domain names. The current RFC (at time of writing) is *RFC 3912*. WHOIS is a network protocol used to query databases for users/ assignees to an internet resource including [domain names](/networking/DNS/DNS.md), [IP addresses](/networking/OSI/IP-addresses.md), and [autonomous names](/networking/ASN.md).
## Details
A Whois server listens on *`port 43`* for requests from a WHOIS client. The request made by the client is a text request, which the server responds to with human-readable text.
### Query
According to the above RFC, the request and response flow looks like this:
```
client                           server at whois.nic.mil

   open TCP   ---- (SYN) ------------------------------>
              <---- (SYN+ACK) -------------------------
   send query ---- "Smith<CR><LF>" -------------------->
   get answer <---- "Info about Smith<CR><LF>" ---------
              <---- "More info about Smith<CR><LF>" ----
   close      <---- (FIN) ------------------------------
              ----- (FIN) ----------------------------->
```
Since the response can have multiple lines in it, each line *is terminated with `CR` and `LF` ASCII characters.* The server ends the connection as soon as it finishes sending the response, so the only indication to the client that the response is fully received is the closing of the TCP connection.

> [!Resources]
> - [RFC 3912](https://datatracker.ietf.org/doc/html/rfc3912)
> - [Wikipedia: WHOIS](https://en.wikipedia.org/wiki/WHOIS#Protocol)
> - [Robots.net: Comprehensive Guide to whois...](https://robots.net/tech/the-comprehensive-guide-to-whois-understanding-domain-and-ip-information/)

> [!Related]
> - [`whois` command](../../CLI-tools/whois.md)
> - `port 43`

