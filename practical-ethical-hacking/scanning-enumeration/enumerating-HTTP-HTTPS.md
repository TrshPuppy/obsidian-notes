
# Enumerating HTTP & HTTPS
Ports 80 and 443 are *normally* assigned to host web services using the [HTTP](/networking/protocols/HTTP.md) and [HTTPS](/networking/protocols/HTTPS.md) protocols (respectively). These protocols are used for communication between a web server and a web browser over the [application layer](/networking/OSI/OSI-reference-model.md) of the OSI model.
## Information Gathering:
Because these ports host web services, they can be visited using a web browser. You can do this by putting the target's IP address into the search bar of a browser, and appending `:80` or `:443` to the end:
```
http://10.0.3.5:80
```

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

> [!Resources]
> - [MDN: User-Agent String Reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent/Firefox)
> - `man curl`

> [!My previous notes (linked in text)]
> - [HTTP](https://github.com/TrshPuppy/obsidian-notes/tree/main/networking/protocols/HTTP.md)
> - [HTTPS](https://github.com/TrshPuppy/obsidian-notes/tree/main/networking/protocols/HTTPS.md)
> - [curl command](https://github.com/TrshPuppy/obsidian-notes/tree/main/CLI-tools/linux/curL.md)
