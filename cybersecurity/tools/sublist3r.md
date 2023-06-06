
# [Sublist3r](https://www.kali.org/tools/sublist3r/)
Sublist3r is a CLI tool written in python which *passively* searched for subdomains using Google, Yahoo, and other search engines including [VirusTotal](/cybersecurity/tools/Virus-Total.md).

Using an integrated tool called *Subbrute* it can be used to perform active subdomain brute forcing against a root domain.

## Usage:
### Dependencies:
- python3
- python3-requests
- python3-dnspython

### Command Line:
```bash
sublist3r -h
usage: sublist3r [-h] -d DOMAIN [-b [BRUTEFORCE]] [-p PORTS] [-v [VERBOSE]]
                 [-t THREADS] [-e ENGINES] [-o OUTPUT] [-n]

OPTIONS:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain name to enumerate it's subdomains
  -b [BRUTEFORCE], --bruteforce [BRUTEFORCE]
                        Enable the subbrute bruteforce module
  -p PORTS, --ports PORTS
                        Scan the found subdomains against specified tcp ports
  -v [VERBOSE], --verbose [VERBOSE]
                        Enable Verbosity and display results in realtime
  -t THREADS, --threads THREADS
                        Number of threads to use for subbrute bruteforce
  -e ENGINES, --engines ENGINES
                        Specify a comma-separated list of search engines
  -o OUTPUT, --output OUTPUT
                        Save the results to text file
  -n, --no-color        Output without color

Example: python3 /usr/bin/sublist3r -d google.com
```

> [!Resources]
> - [Kali: Sublist3r](https://www.kali.org/tools/sublist3r)


