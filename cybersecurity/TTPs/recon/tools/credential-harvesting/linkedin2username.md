
# Linkedin2username
Init.
## Notes on Use
```bash
usage: linkedin2username.py [-h] -c COMPANY [-n DOMAIN] [-d DEPTH]
  [-s SLEEP] [-x PROXY] [-k KEYWORDS] [-g] [-o OUTPUT]

OSINT tool to generate lists of probable usernames from a given company's LinkedIn page.
This tool may break when LinkedIn changes their site.
Please open issues on GitHub to report any inconsistencies.

optional arguments:
  -h, --help            show this help message and exit
  -c COMPANY, --company COMPANY
                        Company name exactly as typed in the company linkedin profile page URL.
  -n DOMAIN, --domain DOMAIN
                        Append a domain name to username output.
                        [example: "-n targetco.com" would output jschmoe@targetco.com]
  -d DEPTH, --depth DEPTH
                        Search depth (how many loops of 25). If unset, will try to grab them
                        all.
  -s SLEEP, --sleep SLEEP
                        Seconds to sleep between search loops. Defaults to 0.
  -x PROXY, --proxy PROXY
                        Proxy server to use. WARNING: WILL DISABLE SSL VERIFICATION.
                        [example: "-p https://localhost:8080"]
  -k KEYWORDS, --keywords KEYWORDS
                        Filter results by a a list of command separated keywords.
                        Will do a separate loop for each keyword,
                        potentially bypassing the 1,000 record limit. 
                        [example: "-k 'sales,human resources,information technology']
  -g, --geoblast        Attempts to bypass the 1,000 record search limit by running
                        multiple searches split across geographic regions.
  -o OUTPUT, --output OUTPUT
                        Output Directory, defaults to li2u-output
```
- turn off MFA on linkedin account using
Grabs each user's display name (including commas) to create emails like `firstname.lastname@company.com`

```bash
python ./linkedin2username.py -c <company name>
```
The `-c` flag should be the company's name *as it appears on LinkedIn*.
### Using `--keyword` to bet past limie
You can get past the 1000 limit by adding keywords:
```bash
-k --keyword 'manager' # for example
```

> [!Resources]
> - [GitHub](https://github.com/initstring/linkedin2username)