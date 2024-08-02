
# WHOIS
A [TCP](../protocols/TCP.md)-based query and response protocol which is used to provide information related to registered domain names. The current RFC (at time of writing) is *RFC 3912*. WHOIS is a network protocol used to query databases for users/ assignees to an internet resource including [domain names](/networking/DNS/DNS.md), [IP addresses](/networking/OSI/IP-addresses.md), and [autonomous names](/networking/ASN.md).
### Data returned from WHOIS:
- Domain Name Registration info: registered domain name + primary and secondary domains
- Registrar Info: name of the registrar (the company which registered the domain)
    - _Registrant Contact:_ individual or organization which registered the domain (including name, address, email, phone number)
    - _Admin Contact:_ the entity responsible for administrative decisions r/t the domain (w/ contact info)
    - _Technical Contact:_ entity responsible for technical aspects of the domain such as server configuration and maintenance
- Domain Status: current status via standardized codes (such as ‘Active’, ‘Pending Renewal’, ‘Expired’, ‘Locked’)
- Nameservers: nameservers assigned to the domain
- Registration Dates & Expiration: when it was first registered, when it was last updated, when it is due to expire
## Request-Response Flow
WHOIS servers listen on port `43` for requests from a client. The request is text-based and the server’s response is human-readable. According to [`RFC 3912`](https://datatracker.ietf.org/doc/html/rfc3912) the communication flow looks like this:
```bash
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

WHOIS databases contain sets of text records for each source. The text records include information related to the resource including assignee info, registrant info, admin info, creation and expiration dates, etc..
## Registries & Registrars
WHOIS servers are operated by registries and registrars. One example of a registry which is responsible for WHOIS data is the [Public Internet Registry](https://en.wikipedia.org/wiki/Public_Interest_Registry). PIR keeps track of all WHOIS info for the `.org` TLD.
### RIRs
There are also Regional Internet Registries (RIRs) which track internet data (including WHOIS data) for specific geolocations. For example, [ARIN](https://en.wikipedia.org/wiki/American_Registry_for_Internet_Numbers) is the RIR for the US, Canada, and parts of the Caribbean and North Atlantic.

The benefit of RIRs is that they _cross reference_ their records. So, if you query ARIN for a record which RIPE (another RIR) is responsible for, the response will include a placeholder _pointing to the RIPE WHOIS server_.
## Lookup Types
There are two models for storing and looking up information in a WHOIS database:
### Thick Lookup
Thick WHOIS servers store _all of the WHOIS information from all registrars for that set of data_. For example, a thick WHOIS server for the `.org` TLD can respond to WHOIS queries for *every `.org` domain.

Thick lookups tend to be _faster_ because only one server needs to be queried.
### Thin Lookup
Thin WHOIS servers only store the _name of the WHOIS server of the registrar of the domain_. The WHOIS server of the registrar has _all of the data_ on that resource. Therefor, a Thin WHOIS server basically _forwards the WHOIS query_ to the WHOIS server that actually has the requested information.
### Variance among domain name registries
Whether a domain (like a TLD) uses the thin or thick model varies and is not standardized. For instance, the `.com` and `.net` TLDs use a thin model and _require domain registrars to maintain their own WHOIS data_.

Other top level registries, like the `.org` TLD, on the other hand, use a thick model.
## Considerations
### GDPR & ICANN
In 2018 the EU implemented GDPR, a regulation which protects the personal information of EU residents specifically. In response, ICANN had to revise WHOIS to comply. This has resulted in the redaction of personal information _from most WHOIS records worldwide_ to streamline compliance. This is why most WHOIS info is redacted.
### RDAP (Registration Data Access Protocol)
💡 Checkout [`RFC 7483`](https://datatracker.ietf.org/doc/rfc7483/)

RDAP is an alternative protocol to WHOIS. Instead of text-based responses, RDAP responses are delivered as `JSON`. Additionally, RDAP is HTTP-based and uses a REST-API style request-response model (it uses URLs to distinguish resources). The only HTTP headers RDAP uses is `HEAD` and `GET`.

The benefit to RDAP over WHOIS is the response format _is standardized_ which makes it easier to automate and parse. For instance, RDAP response objects include direct referrals to other Regional Internet Registries (RIRs), whereas WHOIS does not.

> [!Resources]
> - [RFC 3912](https://datatracker.ietf.org/doc/html/rfc3912)
> - [Wikipedia: WHOIS](https://en.wikipedia.org/wiki/WHOIS#Protocol)
> - [Robots.net: Comprehensive Guide to whois...](https://robots.net/tech/the-comprehensive-guide-to-whois-understanding-domain-and-ip-information/)

> [!Related]
> - [`whois` command](../../CLI-tools/whois.md)
> - `port 43`
> - [RDAP](RDAP.md)

