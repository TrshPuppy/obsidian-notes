
# Aquatone
Tool for creating an overview of an [HTTP](../../../../www/HTTP.md) attack surface of a target. Can scan websites across a large number of hosts.

Init.
## Use
Goes to webpaqges in range and takes a screenshot. Includes services, HTTP response

Give it hosts and ports, it will go out and scan, if it finds an HTTP server, takes a screenshot
### Graph
Dark blue circles: tech running on endpoint

find oauth portalsWhat
## Examples which worked
```bash
cat webhosts.txt | aquatone -ports small -out scans/aquatone -threads 10 -screenshot-timeout 50000 -chrome-path /usr/bin/chromium
```
### Serving report
```bash
aquatone report server --address <IP> 7171

# or with python
python3 -m http.server 7171 --bind <IP>
```


> [!Related]
> - [GoWitness]
> - [EyeWitness]

> [!Resources]
> - [GitHub](https://github.com/michenriksen/aquatone)