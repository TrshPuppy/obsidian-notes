
# GoWitness
Init.
## Examples which worked
```bash
gowitness file -f inscope-subdomains.txt
```
### Serving report
```bash
gowitness report export -f gowitness.html
```
### With Nmap file
```bash
gowitness nmap -f ../../nmap/fullscope-fulltcp.xml --threads 10 | tee gowitness_tee
```