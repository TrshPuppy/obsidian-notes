
# Enumerating HTTP & HTTPS
Ports 80 and 443 are *normally* assigned to host web services using the [HTTP](www/HTTP.md) and [HTTPS](www/HTTPS.md) protocols (respectively). These protocols are used for communication between a web server and a web browser over the [application layer](/networking/OSI/OSI-reference-model.md) of the OSI model.
## Information Gathering:
Ports 80 and 443 being present on a scan of a target indicate the target is likely hosting web services. Investigating these ports is a good way to gather information on the target. You can find out a lot about their architecture, services/ applications they use, etc..
### Via Terminal:
If the target is potentially volatile, or you want to leave less of a trace, you can start by using [`curl`](/CLI-tools/linux/curl.md). With `curl`, you can get the HTML of the entire website. You can also just ask for the headers with the `-I` command, which is sneakier because the response from the target carries less data.
```bash
# Headers only: using wordcount command:
curl -I http://10.0.3.5:80 | wc -c
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current  
								  Dload  Upload   Total   Spent    Left  Speed    0  2890    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0 
293 
# Same command, no flags:
curl http://10.0.3.5:80 | wc -c
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current                                    Dload  Upload   Total   Spent    Left  Speed    100  2890  100  2890    0     0  1473k      0 --:--:-- --:--:-- --:--:-- 2822k  2890
```

You can also conceal yourself further by setting the `User-Agent` header. With `curl` the request sent to the target has a default `User-Agent` of `"curl/7.88.1"`.
```bash
curl -I http://10.0.3.5:80 --verbose
*   Trying 10.0.3.5:80...
* Connected to 10.0.3.5 (10.0.3.5) port 80 (#0)
> HEAD / HTTP/1.1
> Host: 10.0.3.5
> User-Agent: curl/7.88.1     # <--------------------------------
> Accept: */*
> 
< HTTP/1.1 200 OK
HTTP/1.1 200 OK
...
```

You can set this to a less-conspicuous value such as `Mozilla/5.0 (platform; rv:geckoversion) Gecko/geckotrail Firefox/firefoxversion`, using the `-H` flag to set headers.
```bash
curl -I -H "User-Agent: Mozilla/5.0 (platform; rv:geckoversion) Gecko/geckotrail Firefox/firefoxversion" http://10.0.3.5:80 --verbose
*   Trying 10.0.3.5:80... 
* Connected to 10.0.3.5 (10.0.3.5) port 80 (#0)                          
> HEAD / HTTP/1.1                                                        
> Host: 10.0.3.5                                                        
> Accept: */*
> User-Agent: Mozilla/5.0 (platform; rv:geckoversion) Gecko/geckotrail Firefox/firefoxversion
> 
< HTTP/1.1 200 OK
HTTP/1.1 200 OK
...
```
### Via Browser:
Because these ports host web services, they can be visited using a web browser. You can do this by putting the target's IP address into the search bar of a browser, and appending `:80` or `:443` to the end:
```
http://10.0.3.5:80
```
Or by using the browser from your terminal:
```bash
firefox http://10.0.3.5:80
```
![](nested-repos/PNPT-study-guide/PNPT-pics/enumerating-HTTP-HTTPS-1.png)
![](/PNPT-pics/enumerating-HTTP-HTTPS-1.png)
> - Kioptrix VM
## Vulnerability Scanning (w/ `nikto`)
![Notes on Nikto CLI tool](cybersecurity/tools/scanning-enumeration/vuln-scanning/nikto.md)
## Findings
### Hygiene:
By investigating these ports, we can see a default page left up accidentally by the target. This indicates *poor hygiene* and can be included in a pen-test report as a finding.
### Information Disclosure:
The URLs included in the HTML can also tell us more about the target. For example, clicking the link to "DocumentRoot" takes us to another part of the website `http://10.0.3.5:80/manual/mod/core.html#document` where we see a `404` response error code.
![](nested-repos/PNPT-study-guide/PNPT-pics/enumerating-HTTP-HTTPS-2.png)
![](/PNPT-study-guide/PNPT-pics/enumerating-HTTP-HTTPS-2.png)
This page not only tells us that this presumably once-working link is now broken (poor hygiene), we also see *Apache versioning*, and the target's *hostname* (in this case it's localhost). This information is considered *not for us* and can be included in the report under "information disclosure".

> [!Resources]
> - [MDN: User-Agent String Reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent/Firefox)
> - `man curl`

> [!My previous notes (linked in text)]
> - [HTTP](https://github.com/TrshPuppy/obsidian-notes/tree/main/networking/protocols/HTTP.md)
> - [HTTPS](https://github.com/TrshPuppy/obsidian-notes/tree/main/networking/protocols/HTTPS.md)
> - [curl command](https://github.com/TrshPuppy/obsidian-notes/tree/main/CLI-tools/linux/curL.md)
> - [Nikto](https://github.com/TrshPuppy/obsidian-notes/tree/main/cybersecurity/tools/scanning-enumeration/nikto.md)
