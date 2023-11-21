
# DNS lookup utility
Used to manually query *recursive [DNS](/networking/DNS/DNS.md) servers* for info about domains.
## Usage: 
```
dig  [@server] [-b address] [-c class] [-f filename] [-k filename] [-m]
       [-p port#] [-q name] [-t type] [-v] [-x addr]  [-y  [hmac:]name:key]  [
       [-4] | [-6] ] [name] [type] [class] [queryopt...]
```  
```
dig <domain> @<dns-server-ip>
```
Example:
![](/CLI-tools/CLI-tools-pics/dig-1.png) 
> [TryHackMe](https://tryhackme.com/room/dnsindetail)

In response:
### `ANSWER` section: 
Contains the IP address you're looking for.
### `TTL` (Time to Live)
When your computer queries a domain name, it stores the result in local cache. The TTL tells your computer *when to stop considering the record as valid* (when it should request the data again).
![](/CLI-tools/CLI-tools-pics/dig-2.png)

The TTL is measured in seconds. So for this example, the record expires in 2 minutes and 30 seconds

> [!Resources]
> - `man dig`
> - [TryHackMe: DNS in Detail](https://tryhackme.com/room/dnsindetail)
