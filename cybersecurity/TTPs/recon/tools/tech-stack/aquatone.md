
# Aquatone
Tool for creating an overview of an [HTTP](../../../../../www/HTTP.md) attack surface of a target. Can scan websites across a large number of hosts.

Init.
## Use
Goes to webpaqges in range and takes a screenshot. Includes services, HTTP response

Give it hosts and ports, it will go out and scan, if it finds an HTTP server, takes a screenshot
### Ports
- `small: 80, 443`
- `medium: 80, 443, 8000, 8080, 8443 (same as default)`
- `large: 80, 81, 443, 591, 2082, 2087, 2095, 2096, 3000, 8000, 8001, 8008, 8080, 8083, 8443, 8834, 8888`
- `xlarge: 80, 81, 300, 443, 591, 593, 832, 981, 1010, 1311, 2082, 2087, 2095, 2096, 2480, 3000, 3128, 3333, 4243, 4567, 4711, 4712, 4993, 5000, 5104, 5108, 5800, 6543, 7000, 7396, 7474, 8000, 8001, 8008, 8014, 8042, 8069, 8080, 8081, 8088, 8090, 8091, 8118, 8123, 8172, 8222, 8243, 8280, 8281, 8333, 8443, 8500, 8834, 8880, 8888, 8983, 9000, 9043, 9060, 9080, 9090, 9091, 9200, 9443, 9800, 9981, 12443, 16080, 18091, 18092, 20720, 28017`
## Examples which worked
### With urls file
```bash
cat hosts.txt | aquatone -ports small -out scans/aquatone -threads 10 -screenshot-timeout 50000 -chrome-path /usr/bin/chromium
```
### With nmap file
```bash
cat nmap/tcp_web.xml | aquatone -nmap -screenshot-timeout 50000 -out scans/aquatone -threads 10 -chrome-path /usr/bin/chromium
```
### Serving report
```bash
aquatone report server --address <IP> 7171

# or with python
python3 -m http.server 7171 --bind <IP>
```


> [!Related]
> - [gowitness](tech-stack/gowitness.md)
> - [eyewitness](tech-stack/eyewitness.md)

> [!Resources]
> - [GitHub](https://github.com/michenriksen/aquatone)