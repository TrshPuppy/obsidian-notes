
# OWASP Amass for [DNS](/networking/DNS/DNS.md) Enumeration:
>	[Official User Guide](https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md)

Amass is a tool created by [OWASP](/cybersecurity/literature/OWASP.md) to do DNS enumeration. It uses both passive and active techniques, including brute forcing (if you tell it to).

You can also create visualizations of the data you get back from a scan, like graphs and maps, using the API and the `viz` subcommand.

## Configuration File:
Configuration can be supplied to amass using either the config file or the `-config` flag (which takes the path to the file and/ or configuration arguments).

Arguments/ parameters given to the amass command *will take precedence over configurations set in the config file*. I.e. if the file has brute-forcing disabled, but the `-brute` flag was supplied, then amass will perform brute force enumeration.

## Usage:
```bash
Usage: amass intel|enum|viz|track|db [options]

  -h    Show the program usage message
  -help
        Show the program usage message
  -version
        Print the version number of this Amass binary                        

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

Intel will use multiple resources for finding targets including [WHOIS](/CLI-tools/linux/whois.md) lookup and IPv4Info. Like the `enum` subcommand, `intel` use an `-active` mode which will allow it to attempt zone transfers(?) and scan to fetch for SSL/TLS certificates in order to extract extra info.




#### `enum` Subcommand:
This subcommand is for performing enumeration and mapping a network. This helps you determine the attack surface of the target, and what is exposed.

The findings for this subcommand are *stored in a graph database.* The database lives in the Amass' default output folder of a specified output directory (`-dir` flag).

This subcommand can be executed in either a passive or active configuration mode.

##### `-passive`: 
This mode of enum is faster, but will not validate the DNS information (like by resolving subdomains).

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

