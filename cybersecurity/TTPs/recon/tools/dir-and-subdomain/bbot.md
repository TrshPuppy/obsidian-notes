
# BBot
Init.
## Use
### Subdomain Finder
Passive API sources plus a recursive DNS brute-force with target-specific subdomain mutations.
```shell
# find subdomains of evilcorp.com
bbot -t evilcorp.com -p subdomain-enum

# passive sources only
bbot -t evilcorp.com -p subdomain-enum -rf passive
```
#### Make sure to have config file: `subdomain-enum.yml`
```yaml
description: Enumerate subdomains via APIs, brute-force

flags:
  # enable every module with the subdomain-enum flag
  - subdomain-enum

output_modules:
  # output unique subdomains to TXT file
  - subdomains

config:
  dns:
    threads: 25
    brute_threads: 1000
  # put your API keys here
  modules:
    github:
      api_key: ""
    chaos:
      api_key: ""
    securitytrails:
      api_key: ""
```
### Web Spider
```bash
# crawl evilcorp.com, extracting emails and other goodies
bbot -t evilcorp.com -p spider
```
#### Config file: `spider.yml`
```yaml
description: Recursive web spider

modules:
  - httpx

config:
  web:
    # how many links to follow in a row
    spider_distance: 2
    # don't follow links whose directory depth is higher than 4
    spider_depth: 4
    # maximum number of links to follow per page
    spider_links_per_page: 25
```
## Examples which worked
### Make sure to add API keys...
to `~/.config/bbot/bbot.yml
```bash
bbot -t target.com -p subdomain-enum

modules:
  shodan_dns:
    api_key: <key>
```
### Email Gatherer
```bash
# quick email enum with free APIs + scraping
bbot -t evilcorp.com -p email-enum

# pair with subdomain enum + web spider for maximum yield
bbot -t evilcorp.com -p email-enum subdomain-enum spider
```
#### Config`email-enum.yml`
```yaml
description: Enumerate email addresses from APIs, web crawling, etc.

flags:
  - email-enum

output_modules:
  - emails
```
### 4) Web Scanner
```bash
# run a light web scan against www.evilcorp.com
bbot -t www.evilcorp.com -p web-basic

# run a heavy web scan against www.evilcorp.com
bbot -t www.evilcorp.com -p web-thorough
```
#### Config file:`web-basic.yml`
```yaml
description: Quick web scan

include:
  - iis-shortnames

flags:
  - web-basic
```
#### Config:`web-thorough.yml`
```yaml
description: Aggressive web scan

include:
  # include the web-basic preset
  - web-basic

flags:
  - web-thorough
```
### Everything Everywhere All at Once
```bash
# everything everywhere all at once
bbot -t evilcorp.com -p kitchen-sink

# roughly equivalent to:
bbot -t evilcorp.com -p subdomain-enum cloud-enum code-enum email-enum spider web-basic paramminer dirbust-light web-screenshots
```
#### Config:`kitchen-sink.yml`
```yaml
description: Everything everywhere all at once

include:
  - subdomain-enum
  - cloud-enum
  - code-enum
  - email-enum
  - spider
  - web-basic
  - paramminer
  - dirbust-light
  - web-screenshots

config:
  modules:
    baddns:
      enable_references: True
```
> [!Resources]
> - [GitHub](https://github.com/blacklanternsecurity/bbot)