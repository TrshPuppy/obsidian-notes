
# DNS lookup utility
Used to manually query #recursive-DNS-server for info about domains.

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
-tryhackme.com

In response:
- `ANSWER` section: contains the IP address you're looking for.
- `TTL` : #time-to-live:
	- When your computer queries a domain name, it stores the result in local #cache.
	- #TTL tells your computer ==when to stop considering the record as valid== (when it should request the data again)
	- Found in the second column of the answer section:
	- ![](/CLI-tools/CLI-tools-pics/dig-2.png)
	- Measured in seconds
		- For this example, the record exppires in 2 minutes and 30 seconds

### Useful options:

## About:
==helpful for network troubleshooting==


