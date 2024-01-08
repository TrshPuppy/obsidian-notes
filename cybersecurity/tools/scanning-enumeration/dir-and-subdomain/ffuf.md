
# Ffuf (Fuzz Faster U Fool)
Ffuf is a CLI tool used for [directory-enumeration](/cybersecurity/TTPs/recon/directory-enumeration.md). It is *non-recursive*, and will only enumerate at the specified depth in the command.
## Usage:
```bash
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://10.0.2.15/FUZZ
```
In this command the `FUZZ` keyword is used twice; once to tell us how to use the wordlist, and twice to *tell fuff where in the provided URL path it should enumerate.* So, fuff will only be enumerating results at the `FUFF` placeholder in the `-u` URL
### Useful Options
You can give fuff a set of guidelines for the enumeration, including what response status you want returned, whether it should follow redirects, etc..
```bash
ffuf -w wordlist.txt -u 'https://ffuf.io.fi/FUZZ' -mc all -fc 400
```
In this example, fuff will filter out all 400 (bad request) responses.

> [!Resources]
> - [FUFF GitHub Repo](https://github.com/ffuf/ffuf)

