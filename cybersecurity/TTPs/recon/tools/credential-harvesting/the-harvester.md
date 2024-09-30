
# The Harvester
Init.
## Use
Can be used, in conjunction with various API keys, to harvest **[OSINT](../../OSINT.md)** information from multiple sources. 
### API key config file
Create this file: `~/.theHarvester/api-keys.yaml`
```bash
apikeys:
  bevigil:
    key:

  binaryedge:
    key:

  bing:
    key:

  bufferoverun:
    key:

  censys:
    id:
    secret:

  criminalip:
    key:

  fullhunt:
    key:

  github:
    key: example_key

  hunter:
    key: example_key

  hunterhow:
    key:

  intelx:
    key: example_key

  netlas:
    key:

  onyphe:
    key:

  pentestTools:
    key:

  projectDiscovery:
    key: 249cfb33-8885-4e66-b0e1-190ebd94a39d

  rocketreach:
    key:

  securityTrails:
    key:

  shodan:
    key: example_key

  tomba:
    key:
    secret:

  virustotal:
    key:

  zoomeye:
    key:
```
## Examples which worked
### With Intelx as a source
```bash
python3 theHarvester.py -d target.tld -b intelx >> harvester-intelx-out
```
- `-b` tells the Harvester which OSINT source to use, in this case

> [!Resources]
> - [GitHub](https://github.com/laramies/theHarvester/)
