
# Shosubgo
Init.
## Examples which worked
```bash
shosubgo -d target.com -s '<shodan API key>' > shosubout

cat shosub-out | awk '/Domain: /{print}' | awk '{print $2}'
```

> [!Resources]
> - [GitHub](https://github.com/incogbyte/shosubgo)