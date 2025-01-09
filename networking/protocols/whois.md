
# WHOIS
A [TCP](../protocols/TCP.md)-based query and response protocol which is used to provide information related to registered domain names. The current RFC (at time of writing) is *RFC 3912*. WHOIS is a network protocol used to query databases for users/ assignees to an internet resource including [domain names](/networking/DNS/DNS.md), [IP addresses](/networking/OSI/IP-addresses.md), and [autonomous names](/networking/ASN.md).
### Data returned from WHOIS
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
## Querying
ARIN provides multiple avenues for you to query their WHOIS and/or RDAP servers. For the full documentation, click [here](https://www.arin.net/resources/registry/whois/rws/cli/#submitting-a-whois-query-from-a-terminal). Querying ARIN is useful because they’re good about saving WHOIS information about domains from _other registries_. For instance, all WHOIS info for `.org` TLDs is collected and saved by the [Public Internet Registry](https://en.wikipedia.org/wiki/Public_Interest_Registry) (not ARIN).
### With [`curL`](../../CLI-tools/linux/remote/curL.md)
#### **[telnet](telnet.md) WHOIS**
Using curL, you can send a WHOIS query directly to a WHOIS server.
For example, here is a curL request to ARIN’s WHOIS server (`whois.arin.net`) for the IP address `8.8.8.8`. The request is made via telnet:
```bash
    $ echo 8.8.8.8 | curl telnet://whois.arin.net:43
    .. SNIP ..
    
    NetRange:       8.8.8.0 - 8.8.8.255
    CIDR:           8.8.8.0/24
    NetName:        GOGL
    NetHandle:      NET-8-8-8-0-2
    Parent:         NET8 (NET-8-0-0-0-0)
    NetType:        Direct Allocation
    OriginAS:
    Organization:   Google LLC (GOGL)
    RegDate:        2023-12-28
    Updated:        2023-12-28
    Ref:            <https://rdap.arin.net/registry/ip/8.8.8.0>
    
    OrgName:        Google LLC
    OrgId:          GOGL
    Address:        1600 Amphitheatre Parkway
    City:           Mountain View
    StateProv:      CA
    PostalCode:     94043
    Country:        US
    RegDate:        2000-03-30
    Updated:        2019-10-31
    Comment:        Please note that the recommended way to file abuse complaints are located in the following links.
    Comment:
    Comment:        To report abuse and illegal activity: <https://www.google.com/contact/>
    Comment:
    Comment:        For legal requests: <http://support.google.com/legal>
    Comment:
    Comment:        Regards,
    Comment:        The Google Team
    Ref:            <https://rdap.arin.net/registry/entity/GOGL>
    
    OrgTechHandle: ZG39-ARIN
    OrgTechName:   Google LLC
    OrgTechPhone:  +1-650-253-0000
    OrgTechEmail:  arin-contact@google.com
    OrgTechRef:    <https://rdap.arin.net/registry/entity/ZG39-ARIN>
    
    OrgAbuseHandle: ABUSE5250-ARIN
    OrgAbuseName:   Abuse
    OrgAbusePhone:  +1-650-253-0000
    OrgAbuseEmail:  network-abuse@google.com
    OrgAbuseRef:    <https://rdap.arin.net/registry/entity/ABUSE5250-ARIN>
    ```
#### **RDAP**
Notice in the response that ARIN provides a referral address in the `Ref` field. In this case, we can see an HTTPS address to a subdomain referring to RDAP. If we curl it, then we can get our WHOIS data _using RDAP_ (which means the response will be in JSON format).
```bash
    $ curl <https://rdap.arin.net/registry/ip/8.8.8.0>
    {
      "rdapConformance" : [ "nro_rdap_profile_0", "rdap_level_0", "cidr0", "arin_originas0" ],
      "notices" : [ {
        "title" : "Terms of Service",
        "description" : [ "By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use" ],
        "links" : [ {
          "value" : "<https://rdap.arin.net/registry/ip/8.8.8.0>",
          "rel" : "terms-of-service",
          "type" : "text/html",
          "href" : "<https://www.arin.net/resources/registry/whois/tou/>"
        } ]
      }, {
        "title" : "Whois Inaccuracy Reporting",
        "description" : [ "If you see inaccuracies in the results, please visit: " ],
        "links" : [ {
          "value" : "<https://rdap.arin.net/registry/ip/8.8.8.0>",
          "rel" : "inaccuracy-report",
          "type" : "text/html",
          "href" : "<https://www.arin.net/resources/registry/whois/inaccuracy_reporting/>"
        } ]
      }, {
        "title" : "Copyright Notice",
        "description" : [ "Copyright 1997-2024, American Registry for Internet Numbers, Ltd." ]
      } ],
      "handle" : "NET-8-8-8-0-2",
      "startAddress" : "8.8.8.0",
      "endAddress" : "8.8.8.255",
      "ipVersion" : "v4",
      "name" : "GOGL",
      "type" : "DIRECT ALLOCATION",
      "parentHandle" : "NET-8-0-0-0-0",
      "events" : [ {
        "eventAction" : "last changed",
        "eventDate" : "2023-12-28T17:24:56-05:00"
      }, {
        "eventAction" : "registration",
        "eventDate" : "2023-12-28T17:24:33-05:00"
      } ],
      "links" : [ {
        "value" : "<https://rdap.arin.net/registry/ip/8.8.8.0>",
        "rel" : "self",
        "type" : "application/rdap+json",
        "href" : "<https://rdap.arin.net/registry/ip/8.8.8.0>"
      }, {
        "value" : "<https://rdap.arin.net/registry/ip/8.8.8.0>",
        "rel" : "alternate",
        "type" : "application/xml",
        "href" : "<https://whois.arin.net/rest/net/NET-8-8-8-0-2>"
      } ],
      "entities" : [ {
        "handle" : "GOGL",
        "vcardArray" : [ "vcard", [ [ "version", { }, "text", "4.0" ], [ "fn", { }, "text", "Google LLC" ], [ "adr",
    {
          "label" : "1600 Amphitheatre Parkway\\nMountain View\\nCA\\n94043\\nUnited States"
        }, "text", [ "", "", "", "", "", "", "" ] ], [ "kind", { }, "text", "org" ] ] ],
        "roles" : [ "registrant" ],
        "remarks" : [ {
          "title" : "Registration Comments",
          "description" : [ "Please note that the recommended way to file abuse complaints are located in the following links. ", "", "To report abuse and illegal activity: <https://www.google.com/contact/>", "", "For legal requests: <http://support.google.com/legal> ", "", "Regards, ", "The Google Team" ]
        } ],
        "links" : [ {
          "value" : "<https://rdap.arin.net/registry/ip/8.8.8.0>",
          "rel" : "self",
          "type" : "application/rdap+json",
          "href" : "<https://rdap.arin.net/registry/entity/GOGL>"
        }, {
          "value" : "<https://rdap.arin.net/registry/ip/8.8.8.0>",
          "rel" : "alternate",
          "type" : "application/xml",
          "href" : "<https://whois.arin.net/rest/org/GOGL>"
        } ],
        "events" : [ {
          "eventAction" : "last changed",
          "eventDate" : "2019-10-31T15:45:45-04:00"
        }, {
          "eventAction" : "registration",
          "eventDate" : "2000-03-30T00:00:00-05:00"
        } ],
        "entities" : [ {
          "handle" : "ABUSE5250-ARIN",
          "vcardArray" : [ "vcard", [ [ "version", { }, "text", "4.0" ], [ "adr", {
            "label" : "1600 Amphitheatre Parkway\\nMountain View\\nCA\\n94043\\nUnited States"
          }, "text", [ "", "", "", "", "", "", "" ] ], [ "fn", { }, "text", "Abuse" ], [ "org", { }, "text", "Abuse"
    ], [ "kind", { }, "text", "group" ], [ "email", { }, "text", "network-abuse@google.com" ], [ "tel", {
            "type" : [ "work", "voice" ]
          }, "text", "+1-650-253-0000" ] ] ],
          "roles" : [ "abuse" ],
          "remarks" : [ {
            "title" : "Registration Comments",
            "description" : [ "Please note that the recommended way to file abuse complaints are located in the following links.", "", "To report abuse and illegal activity: <https://www.google.com/contact/>", "", "For legal requests: <http://support.google.com/legal> ", "", "Regards,", "The Google Team" ]
          } ],
          "links" : [ {
            "value" : "<https://rdap.arin.net/registry/ip/8.8.8.0>",
            "rel" : "self",
            "type" : "application/rdap+json",
            "href" : "<https://rdap.arin.net/registry/entity/ABUSE5250-ARIN>"
          }, {
            "value" : "<https://rdap.arin.net/registry/ip/8.8.8.0>",
            "rel" : "alternate",
            "type" : "application/xml",
            "href" : "<https://whois.arin.net/rest/poc/ABUSE5250-ARIN>"
          } ],
          "events" : [ {
            "eventAction" : "last changed",
            "eventDate" : "2022-10-24T08:43:11-04:00"
          }, {
            "eventAction" : "registration",
            "eventDate" : "2015-11-06T15:36:35-05:00"
          } ],
          "status" : [ "validated" ],
          "port43" : "whois.arin.net",
          "objectClassName" : "entity"
        }, {
          "handle" : "ZG39-ARIN",
          "vcardArray" : [ "vcard", [ [ "version", { }, "text", "4.0" ], [ "adr", {
            "label" : "1600 Amphitheatre Parkway\\nMountain View\\nCA\\n94043\\nUnited States"
          }, "text", [ "", "", "", "", "", "", "" ] ], [ "fn", { }, "text", "Google LLC" ], [ "org", { }, "text", "Google LLC" ], [ "kind", { }, "text", "group" ], [ "email", { }, "text", "arin-contact@google.com" ], [ "tel", {
            "type" : [ "work", "voice" ]
          }, "text", "+1-650-253-0000" ] ] ],
          "roles" : [ "technical", "administrative" ],
          "links" : [ {
            "value" : "<https://rdap.arin.net/registry/ip/8.8.8.0>",
            "rel" : "self",
            "type" : "application/rdap+json",
            "href" : "<https://rdap.arin.net/registry/entity/ZG39-ARIN>"
          }, {
            "value" : "<https://rdap.arin.net/registry/ip/8.8.8.0>",
            "rel" : "alternate",
            "type" : "application/xml",
            "href" : "<https://whois.arin.net/rest/poc/ZG39-ARIN>"
          } ],
          "events" : [ {
            "eventAction" : "last changed",
            "eventDate" : "2023-11-10T07:01:59-05:00"
          }, {
            "eventAction" : "registration",
            "eventDate" : "2000-11-30T13:54:08-05:00"
          } ],
          "status" : [ "validated" ],
          "port43" : "whois.arin.net",
          "objectClassName" : "entity"
        } ],
        "port43" : "whois.arin.net",
        "objectClassName" : "entity"
      } ],
      "port43" : "whois.arin.net",
      "status" : [ "active" ],
      "objectClassName" : "ip network",
      "cidr0_cidrs" : [ {
        "v4prefix" : "8.8.8.0",
        "length" : 24
      } ],
      "arin_originas0_originautnums" : [ ]
    }%
    ```
### With [`whois`](../../CLI-tools/whois.md)
`whois` is a Linux command line WHOIS client which you can use to query name servers. A standard `whois` command looks like this:
```bash
whois megacorpone.com
.. SNIP ..

   Domain Name: MEGACORPONE.COM
   Registry Domain ID: 1775445745_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.gandi.net
   Registrar URL: <http://www.gandi.net>
   Updated Date: 2024-12-22T21:09:21Z

.. SNIP ..
```
#### **Reverse WHOIS**
We can also use `whois` to do a reverse WHOIS query on an IP address which will give. us information related to _who is hosting the IP_.
```bash
whois 38.100.193.70
.. SNIP ..

NetRange:       38.0.0.0 - 38.255.255.255
CIDR:           38.0.0.0/8
NetName:        COGENT-A
NetHandle:      NET-38-0-0-0-1
Parent:          ()
NetType:        Direct Allocation
OriginAS:       AS174
Organization:   PSINet, Inc. (PSI)
RegDate:        1991-04-16
Updated:        2023-10-11
Comment:        IP allocations within 38.0.0.0/8 are used for Cogent customer static IP assignments.
```
## Considerations
### GDPR & ICANN
In 2018 the EU implemented GDPR, a regulation which protects the personal information of EU residents specifically. In response, ICANN had to revise WHOIS to comply. This has resulted in the redaction of personal information _from most WHOIS records worldwide_ to streamline compliance. This is why most WHOIS info is redacted.
### [RDAP](RDAP.md) (Registration Data Access Protocol)
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

