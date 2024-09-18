
# Subfinder
Init.
## Examples which worked
```bash
subfinder -d target.com -all -stats -o subfinder_out.json -oJ -oI

subfinder -d target.com -s chaos -stats
```
### Awk
```bash
cat subfinder_out.json| jq | awk '/"host"/ {print}' | cut -d '│Nmap done: 1067 IP addresses (1067 hosts up) scanned in 98161.08 seconds
"' -f 4 > subfinder_subdomains.txt
```

> [!Resources]
> - [GitHub](https://github.com/projectdiscovery/subfinder?tab=readme-ov-file)
