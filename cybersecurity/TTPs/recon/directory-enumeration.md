
# Directory Busting/ Enumeration
Directory busting is a TTP in which the endpoints of a website are enumerated by trying a bunch of different words (usually from a wordlist), appending them to a URL, and attempting to visit them and see what status code/ information they might return.

There are multiple tools which can be used to accomplish this. Some of which do a *recursive search* ([feroxbuster](tools/dir-and-subdomain/feroxbuster.md), [dirb](tools/dir-and-subdomain/dirb.md)) while others do non-recursive searching ([ffuf](tools/dir-and-subdomain/ffuf.md), [gobuster](tools/dir-and-subdomain/gobuster.md)).

> [!Related tools]
> - [gobuster](tools/dir-and-subdomain/gobuster.md)
> - [feroxbuster](tools/dir-and-subdomain/feroxbuster.md)
> - [ffuf](tools/dir-and-subdomain/ffuf.md)
> - [gobuster](tools/dir-and-subdomain/gobuster.md)
