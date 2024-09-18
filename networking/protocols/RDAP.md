
# Registration Data Access Protocol (RDAP)
An alternative protocol to [WHOIS](WHOIS.md) which can be used to query *registration data from DNRs* (Domain Name Registrars) and *RIRs* (Regional Internet Registries). Responses to clients are delivered in [JSON](/coding/data-structures/JSON) format, which is different than WHOIS which returns data in text.

RDAP differs from WHOIS because it is a [HTTP](../../www/HTTP.md)-based [REST-API](../../coding/APIs/REST-API.md) style protocol and its responses *are standardized*. Because RDAP is HTTP/S based, it *uses URLS* to distinguish resources. The only HTTP methods used by RDAP are *HEAD* and *GET*.
## Compared to WHOIS
The benefit to RDAP over WHOIS is the response format is standardized which makes it easier to automate and parse. For instance, RDAP response objects include direct referrals to other Regional Internet Registries (RIRs), whereas WHOIS does not.

> [!Resources]
> - [Datatracker: RFC 7483](https://datatracker.ietf.org/doc/rfc7483/)
> - [ARIN: RDAP](https://www.arin.net/resources/registry/whois/rdap/)

> [!Related]
> - [WHOIS](WHOIS.md)
> - `RFC 7483`

