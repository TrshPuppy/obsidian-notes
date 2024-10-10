
# Shosubgo
Init.
## Use
### Quick Start
```bash
go install github.com/incogbyte/shosubgo@latest
```
## Examples which worked
```bash
shosubgo -d target.com -s '<shodan API key>' > shosubout

cat shosub-out | awk '/Domain: /{print}' | awk '{print $2}'
```
### Using a file of apex domains
```bash
shosubgo -f apex.txt -s '<shodan API key>' > shosubout-apex
```

> [!Resources]
> - [GitHub](https://github.com/incogbyte/shosubgo)