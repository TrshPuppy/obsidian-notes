
# OWASP Amass for [DNS](/networking/DNS/DNS.md) Enumeration:
>	[Official User Guide](https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md)

Amass is a tool created by [OWASP](cybersecurity/literature/OWASP.md) to do DNS enumeration. It uses both passive and active techniques, including brute forcing (if you tell it to).

You can also create visualizations of the data you get back from a scan, like graphs and maps, using the API and the `viz` subcommand.

## Configuration File:
Configuration can be supplied to amass using either the config file or the `-config` flag (which takes the path to the file and/ or configuration arguments).

Arguments/ parameters given to the amass command *will take precedence over configurations set in the config file*. I.e. if the file has brute-forcing disabled, but the `-brute` flag was supplied, then amass will perform brute force enumeration.

### Location:
The location of the config file can be specified with the `-config` flag or by setting the `AMASS_CONFIG` env variable. The file should be called `config.ini`. This will allow Amass to attempt to find it.
- Linux: `$HOME/.config/amass/config.ini` or `/etc/amass/config.ini`
- Windows: `%AppData%\amass\config.ini`
- Apple: `$HOME/Library/Application Support/amass/config.ini`

#### Output Directory:
The location of the config file is dependent on the *output directory*. Using the `-dir` flag will change the location Amass will use to try and discover the file. For example, if you use `-dir /my/ouput/dir` Amass will go there to look for `config.ini`

### Config file sections:
#### Default Section:

| Option | Description |
|--------|-------------|
| mode | Determines which mode the enumeration is performed in: default, passive or active |
| output_directory | The directory that stores the graph database and other output files |
| maximum_dns_queries | The maximum number of concurrent DNS queries that can be performed |

#### `resolvers` Section:

| Option | Description |
|--------|-------------|
| resolver | The IP address of a DNS resolver and used globally by the amass package |

#### `scope` Section:

| Option | Description |
|--------|-------------|
| address | IP address or range (e.g. a.b.c.10-245) that is in scope |
| asn | ASN that is in scope |
| cidr | CIDR (e.g. 192.168.1.0/24) that is in scope |
| port | Specifies a port to be used when actively pulling TLS certificates or crawling |

#### `scope.domains` Section:

| Option | Description |
|--------|-------------|
| domain | A root DNS domain name to be added to the enumeration scope |

#### The `scope.blacklisted` Section:

| Option | Description |
|--------|-------------|
| subdomain | A DNS subdomain name to be considered out of scope during the enumeration |

#### The `graphdbs` Section:

##### The `graphdbs.postgres` Section:

| Option | Description |
|--------|-------------|
| primary | When set to true, the graph database is specified as the primary db |
| url | URL in the form of "postgres://[username:password@]host[:port]/database-name?sslmode=disable" where Amass will connect to a PostgreSQL database |
| options | Additional PostgreSQL database options |

##### The `graphdbs.mysql` Section:

| Option | Description |
|--------|-------------|
| url | URL in the form of "[username:password@]tcp(host[:3306])/database-name?timeout=10s" where Amass will connect to a MySQL database |

#### The `bruteforce` Section:

| Option | Description |
|--------|-------------|
| enabled | When set to true, brute forcing is performed during the enumeration |
| recursive | When set to true, brute forcing is performed on discovered subdomain names as well |
| minimum_for_recursive | Number of discoveries made in a subdomain before performing recursive brute forcing |
| wordlist_file | Path to a custom wordlist file to be used during the brute forcing |

#### The `alterations` Section:

| Option | Description |
|--------|-------------|
| enabled | When set to true, permuting resolved DNS names is performed during the enumeration |
| edit_distance | Number of times an edit operation will be performed on a name sample during fuzzy label searching |
| flip_words | When set to true, causes words in DNS names to be exchanged for others in the alteration word list |
| flip_numbers | When set to true, causes numbers in DNS names to be exchanged for other numbers |
| add_words | When set to true, causes other words in the alteration word list to be added to resolved DNS names |
| add_numbers | When set to true, causes numbers to be added and removed from resolved DNS names |
| wordlist_file | Path to a custom wordlist file that provides additional words to the alteration word list |

#### The `data_sources` Section:

| Option | Description |
|--------|-------------|
| ttl | The number of minutes that the responses of **all** data sources for the target are cached |

##### The `data_sources.SOURCENAME` Section:

| Option | Description |
|--------|-------------|
| ttl | The number of minutes that the response of the data source for the target is cached |

###### The `data_sources.SOURCENAME.CREDENTIALSETID` Section:

| Option | Description |
|--------|-------------|
| apikey | The API key to be used when accessing the data source |
| secret | An additional secret to be used with the API key |
| username | User for the data source account |
| password | Valid password for the user identified by the 'username' option |

##### The `data_sources.disabled` Section:

| Option | Description |
|--------|-------------|
| data_source | One of the Amass data sources that is **not** to be used during the enumeration |

## Graph Database:
All findings outputted from an Amass enumeration are stored in a graph database. The graph db is either located in a file in the output directory, or can be connected to remotely using settings in the config file.

If a new enumeration is started and there is already a graph db from a previous enumeration *of the same target*, the new enumeration *will use the subdomain names found during the previous enumeration.*

New DNS queries will also be run on the subdomains to make sure they still are legitimate and have current IP addresses.

Results from each enumeration are stored separately in the db. The `track` subcommand can be used to look for differences between them. 

### Cayley Graph Schema:
The graph db stores all the domains found during an enumeration including associated info like IP, NS Records, CNAME, A Record, IP Block, etc.. Each enumeration has an associated, unique UUID.

#### *BONUS:*
Graphs can also be imported into [Maltego](https://www.maltego.com/product-features/).
`amass viz -maltego` <-- converts Amass data to Maltego CSV file.

## Usage:
```bash
Usage: amass intel|enum|viz|track|db [options]

  -h       Show the program usage message
  -help    Show the program usage message
  -version Print the version number of this Amass binary                  
Subcommands: 
        amass intel - Discover targets for enumerations                   
        amass enum  - Perform enumerations and network mapping            
        amass viz   - Visualize enumeration results                       
        amass track - Track differences between enumerations              
        amass db    - Manipulate the Amass graph database
```

### Subcommands:
Amass has a few useful subcommands/ modules which make it very powerful:

#### `intel` Subcommand:
This subcommand will collect *open source* intel on the target org/ domain. It's useful for discovering [root domains](/networking/DNS/DNS.md) associated with the target and for finding *targets for enumeration*.
```bash
amass intel -h
sage: amass intel [options] [-whois -d DOMAIN] [-addr ADDR -asn ASN -cidr CIDR]  
  -active      
        Attempt certificate name grabs                                                                              
  -addr value                    
        IPs and ranges (192.168.1.1-254) separated by commas
  -asn value                      
        ASNs separated by commas (can be used multiple times) 
  -cidr value                      
        CIDRs separated by commas (can be used multiple times)
...
```

Intel will use multiple resources for finding targets including [WHOIS](/CLI-tools/linux/whois.md) lookup and IPv4Info. Like the `enum` subcommand, `intel` has an `-active` mode which will allow it to attempt zone transfers(?) and scan to fetch for SSL/TLS certificates in order to extract extra info.

| Flag | Description | Example |
|------|-------------|---------|
| -active | Enable active recon methods | amass intel -active -addr 192.168.2.1-64 -p 80,443,8080 |
| -addr | IPs and ranges (192.168.1.1-254) separated by commas | amass intel -addr 192.168.2.1-64 |
| -asn | ASNs separated by commas (can be used multiple times) | amass intel -asn 13374,14618 |
| -cidr | CIDRs separated by commas (can be used multiple times) | amass intel -cidr 104.154.0.0/15 |
| -d | Domain names separated by commas (can be used multiple times) | amass intel -whois -d example.com |
| -demo | Censor output to make it suitable for demonstrations | amass intel -demo -whois -d example.com |
| -df | Path to a file providing root domain names | amass intel -whois -df domains.txt |
| -ef | Path to a file providing data sources to exclude | amass intel -whois -ef exclude.txt -d example.com |
| -exclude | Data source names separated by commas to be excluded | amass intel -whois -exclude crtsh -d example.com |
| -if | Path to a file providing data sources to include | amass intel -whois -if include.txt -d example.com |
| -include | Data source names separated by commas to be included | amass intel -whois -include crtsh -d example.com |
| -ip | Show the IP addresses for discovered names | amass intel -ip -whois -d example.com |
| -ipv4 | Show the IPv4 addresses for discovered names | amass intel -ipv4 -whois -d example.com |
| -ipv6 | Show the IPv6 addresses for discovered names | amass intel -ipv6 -whois -d example.com |
| -list | Print the names of all available data sources | amass intel -list |
| -log | Path to the log file where errors will be written | amass intel -log amass.log -whois -d example.com |
| -max-dns-queries | Maximum number of concurrent DNS queries | amass intel -max-dns-queries 200 -whois -d example.com |
| -o | Path to the text output file | amass intel -o out.txt -whois -d example.com |
| -org | Search string provided against AS description information | amass intel -org Facebook |
| -p | Ports separated by commas (default: 80, 443) | amass intel -cidr 104.154.0.0/15 -p 443,8080 |
| -r | IP addresses of preferred DNS resolvers (can be used multiple times) | amass intel -r 8.8.8.8,1.1.1.1 -whois -d example.com |
| -rf | Path to a file providing preferred DNS resolvers | amass intel -rf data/resolvers.txt -whois -d example.com |
| -src | Print data sources for the discovered names | amass intel -src -whois -d example.com |
| -timeout | Number of minutes to execute the enumeration | amass intel -timeout 30 -d example.com |
| -v | Output status / debug / troubleshooting info | amass intel -v -whois -d example.com |
| -whois | All discovered domains are run through reverse whois | amass intel -whois -d example.com |

#### `enum` Subcommand:
This subcommand is for performing enumeration and mapping a network. This helps you determine the attack surface of the target and what is exposed.

The findings for this subcommand are *stored in a graph database.* The database lives in the Amass default output folder or a specified output directory (`-dir` flag).

This subcommand can be executed in either a normal, a passive, or an active configuration mode.

##### `-normal`:
Will use data sources to enumerate and will use DNS to *validate findings and investigate the namescpaes in scope* (the domain names given to the command).
`amass enum -d example.com`

##### `-passive`: 
This mode of `enum` is faster, but will not validate the DNS information (like by resolving subdomains).

This can be useful for monitoring a target's attack surface because it will return all subdomains that have been used (*and may be re-used in the future*).
```bash
amass enum -passive -d owasp.org -src
[DNSSpy]          calendar.owasp.org
[AnubisDB]        kerala.owasp.org
[Arquivo]         5c4171004230818351034.owasp.org
[SiteDossier]     owasp4.owasp.org
[Google]          devsecops.owasp.org
[Arquivo]         ads.owasp.org
[AnubisDB]        training.owasp.org
...
```
The `-src` flag tells Amass to include the source of each result in the output (ex: `[DNSSpy]`). The `-d` flag just allows us to list multiple domains separated by a comma.

##### `-active:
The `-active` flag and the active configuration state are different things(?). In this mode, the results are *more accurate* but are obtained using techniques such as *brute forcing*.

The `-active` flag also gathers intel by enabling "zone transfers" and  post scanning of SSL/TLS services. It extracts additional subdomain results by grabbing certificates and scanning for subdomains in their fields.
![](/cybersecurity/cybersecurity-pics/amass-1.png)
>	[OWASP Amass GitHub: Tutorial](https://github.com/owasp-amass/amass/wiki/Tutorial#amass-intel)

In the above image amass is enumerating DNS for the target `owasp.org` by brute forcing (`-brute`) with a wordlist (`-w` `/path/to/wordlist`). The output will list the sources (`-src`) and each result's associated [IP address](/networking/OSI/IP-addresses.md) (`-ip`).

The config file amass will use for this command is specified using the `-config /path/to/config.txt` flag, and the output for the results is indicated with the `-o /path/to/output/file.txt` flag.

| Flag | Description | Example |
|------|-------------|---------|
| -active | Enable active recon methods | amass enum -active -d example.com -p 80,443,8080 |
| -alts | Enable generation of altered names | amass enum -alts -d example.com |
| -aw | Path to a different wordlist file for alterations | amass enum -aw PATH -d example.com |
| -awm | "hashcat-style" wordlist masks for name alterations | amass enum -awm dev?d -d example.com |
| -bl | Blacklist of subdomain names that will not be investigated | amass enum -bl blah.example.com -d example.com |
| -blf | Path to a file providing blacklisted subdomains | amass enum -blf data/blacklist.txt -d example.com |
| -brute | Perform brute force subdomain enumeration | amass enum -brute -d example.com |
| -d | Domain names separated by commas (can be used multiple times) | amass enum -d example.com |
| -demo | Censor output to make it suitable for demonstrations | amass enum -demo -d example.com |
| -df | Path to a file providing root domain names | amass enum -df domains.txt |
| -dns-qps | Maximum number of DNS queries per second across all resolvers | amass enum -dns-qps 200 -d example.com |
| -ef | Path to a file providing data sources to exclude | amass enum -ef exclude.txt -d example.com |
| -exclude | Data source names separated by commas to be excluded | amass enum -exclude crtsh -d example.com |
| -if | Path to a file providing data sources to include | amass enum -if include.txt -d example.com |
| -iface | Provide the network interface to send traffic through | amass enum -iface en0 -d example.com |
| -include | Data source names separated by commas to be included | amass enum -include crtsh -d example.com |
| -ip | Show the IP addresses for discovered names | amass enum -ip -d example.com |
| -ipv4 | Show the IPv4 addresses for discovered names | amass enum -ipv4 -d example.com |
| -ipv6 | Show the IPv6 addresses for discovered names | amass enum -ipv6 -d example.com |
| -json | Path to the JSON output file | amass enum -json out.json -d example.com |
| -list | Print the names of all available data sources | amass enum -list |
| -log | Path to the log file where errors will be written | amass enum -log amass.log -d example.com |
| -max-depth | Maximum number of subdomain labels for brute forcing | amass enum -brute -max-depth 3 -d example.com |
| -max-dns-queries | Deprecated flag to be replaced by dns-qps in version 4.0 | amass enum -max-dns-queries 200 -d example.com |
| -min-for-recursive | Subdomain labels seen before recursive brute forcing (Default: 1) | amass enum -brute -min-for-recursive 3 -d example.com |
| -nf | Path to a file providing already known subdomain names (from other tools/sources) | amass enum -nf names.txt -d example.com |
| -norecursive | Turn off recursive brute forcing | amass enum -brute -norecursive -d example.com |
| -o | Path to the text output file | amass enum -o out.txt -d example.com |
| -oA | Path prefix used for naming all output files | amass enum -oA amass_scan -d example.com |
| -p | Ports separated by commas (default: 443) | amass enum -d example.com -p 443,8080 |
| -passive | A purely passive mode of execution | amass enum -passive -d example.com |
| -r | IP addresses of untrusted DNS resolvers (can be used multiple times) | amass enum -r 8.8.8.8,1.1.1.1 -d example.com |
| -rf | Path to a file providing untrusted DNS resolvers | amass enum -rf data/resolvers.txt -d example.com |
| -rqps | Maximum number of DNS queries per second for each untrusted resolver | amass enum -rqps 10 -d example.com |
| -scripts | Path to a directory containing ADS scripts | amass enum -scripts PATH -d example.com |
| -src | Print data sources for the discovered names | amass enum -src -d example.com |
| -timeout | Number of minutes to execute the enumeration | amass enum -timeout 30 -d example.com |
| -tr | IP addresses of trusted DNS resolvers (can be used multiple times) | amass enum -tr 8.8.8.8,1.1.1.1 -d example.com |
| -trf | Path to a file providing trusted DNS resolvers | amass enum -trf data/trusted.txt -d example.com |
| -trqps | Maximum number of DNS queries per second for each trusted resolver | amass enum -trqps 20 -d example.com |
| -v | Output status / debug / troubleshooting info | amass enum -v -d example.com |
| -w | Path to a different wordlist file for brute forcing | amass enum -brute -w wordlist.txt -d example.com |
| -wm | "hashcat-style" wordlist masks for DNS brute forcing | amass enum -brute -wm ?l?l -d example.com |

#### `viz` Subcommand:
Use this subcommand to add visual detail to the output data. This command will use the `output_directory` and remote graph database settings configured in the configuration file to create network graphs.

The generated graphs will be output to the current working directory and named `amass_TYPE`.
![](/cybersecurity/cybersecurity-pics/amass-2.png)
>	[Amass GitHub](https://github.com/owasp-amass/amass/blob/master/images/network_06092018.png)

| Flag | Description | Example |
|------|-------------|---------|
| -d | Domain names separated by commas (can be used multiple times) | amass viz -d3 -d example.com |
| -d3 | Output a D3.js v4 force simulation HTML file | amass viz -d3 -d example.com |
| -df | Path to a file providing root domain names | amass viz -d3 -df domains.txt |
| -dot | Generate the DOT output file | amass viz -dot -d example.com |
| -enum | Identify an enumeration via an index from the db listing | amass viz -enum 1 -d3 -d example.com |
| -gexf | Output to Graph Exchange XML Format (GEXF) | amass viz -gexf -d example.com |
| -graphistry | Output Graphistry JSON | amass viz -graphistry -d example.com |
| -i | Path to the Amass data operations JSON input file | amass viz -d3 -d example.com |
| -maltego | Output a Maltego Graph Table CSV file | amass viz -maltego -d example.com |
| -o | Path to a pre-existing directory that will hold output files | amass viz -d3 -o OUTPATH -d example.com |
| -oA | Prefix used for naming all output files | amass viz -d3 -oA example -d example.com |

#### `track` Subcommand:
This subcommand can be used to show differences between multiple enumerations done on the same target. You can use it to monitor a target's attack surface and any changes to it over time. 

Uses the `output_directory` and remote graph db settings in the config file.

| Flag | Description | Example |
|------|-------------|---------|
| -d | Domain names separated by commas (can be used multiple times) | amass track -d example.com |
| -df | Path to a file providing root domain names | amass track -df domains.txt |
| -history | Show the difference between all enumeration pairs | amass track -history |
| -last | The number of recent enumerations to include in the tracking | amass track -last NUM |
| -since | Exclude all enumerations before a specified date (format: 01/02 15:04:05 2006 MST) | amass track -since DATE |

#### `db` Subcommand:
Use this subcommand to view and manipulate the graph database.

| Flag | Description | Example |
|------|-------------|---------|
| -d | Domain names separated by commas (can be used multiple times) | amass db -d example.com |
| -demo | Censor output to make it suitable for demonstrations | amass db -demo -d example.com |
| -df | Path to a file providing root domain names | amass db -df domains.txt |
| -enum | Identify an enumeration via an index from the listing | amass db -enum 1 -show |
| -ip | Show the IP addresses for discovered names | amass db -show -ip -d example.com |
| -ipv4 | Show the IPv4 addresses for discovered names | amass db -show -ipv4 -d example.com |
| -ipv6 | Show the IPv6 addresses for discovered names | amass db -show -ipv6 -d example.com |
| -json | Path to the JSON output file or '-' | amass db -names -silent -json out.json -d example.com |
| -list | Print enumerations in the database and filter on domains specified | amass db -list |
| -names | Print just discovered names | amass db -names -d example.com |
| -o | Path to the text output file | amass db -names -o out.txt -d example.com |
| -show | Print the results for the enumeration index + domains provided | amass db -show |
| -src | Print data sources for the discovered names | amass db -show -src -d example.com |
| -summary | Print just ASN table summary | amass db -summary -d example.com |

> [!Resources:]
> - [OWASP Amass User Guide](https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md)
> - [Maltego](https://www.maltego.com/product-features/)

