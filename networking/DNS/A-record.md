
# Domain A Records
An A record is what *maps the IP address of the computer hosting a domain to the domain name*. The 'A' stands for 'Address'. The *Name Server* contains the A record which points to the associated [IP address](/networking/OSI/IP-addresses.md). When a request is made for that IP address (for example, by a client web browser), the request is *directed to the IP address in the A record*.

A records are specified by [`RFC 1035`](https://www.rfc-editor.org/rfc/rfc1035).
## Redundancy
Domains can have *multiple A records* to create redundancy. Additionally, *multiple domains can point to one address*. Each domain would have its own A record pointing to that IP address.

> [!Resources]
> - [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035)
> - [DNSimple: A Record](https://support.dnsimple.com/articles/a-record/)

