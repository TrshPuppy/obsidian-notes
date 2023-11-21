

# `nmblookup` CLI tool:
`nmblookup` is a CLI tool which resolves the NetBIOS names of devices on a network to their [IP addresses](/networking/OSI/IP-addresses.md). It does so by making use of queries being made on the network. This tool is part of the [samba](/networking/protocols/SMB.md) suite of tools.

`nmblookup` sends [NetBios](/networking/protocols/NetBIOS.md) name queries across an IP broadcast area in order to map the names to IP addresses. All of the queries are made of [UDP](/networking/protocols/UDP.md).
## Usage
```bash
nmblookup --help
Usage: <NODE> ...
  -B, --broadcast=BROADCAST-ADDRESS         Specify address to use for broadcasts
  -f, --flags                               List the NMB flags returned
  -U, --unicast=STRING                      Specify address to use for unicast
  -M, --master-browser                      Search for a master browser
      --recursion                           Set recursion desired in package
  -S, --status                              Lookup node status as well
  -T, --translate                           Translate IP addresses into names
  -r, --root-port                           Use root port 137 (Win95 only replies to this)
  -A, --lookup-by-ip                        Do a node status on <name> as an IP Address

Help options:
  -?, --help                                Show this help message
      --usage                               Display brief usage message

Common Samba options:
  -d, --debuglevel=DEBUGLEVEL               Set debug level
      --debug-stdout                        Send debug output to standard output
  -s, --configfile=CONFIGFILE               Use alternative configuration file
      --option=name=value                   Set smb.conf option from command line
  -l, --log-basename=LOGFILEBASE            Basename for log/debug files
      --leak-report                         enable talloc leak reporting on exit
      --leak-report-full                    enable full talloc leak reporting on exit

Connection options:
  -R, --name-resolve=NAME-RESOLVE-ORDER     Use these name resolution services only
  -O, --socket-options=SOCKETOPTIONS        socket options to use
  -m, --max-protocol=MAXPROTOCOL            Set max protocol level
  -n, --netbiosname=NETBIOSNAME             Primary netbios name
      --netbios-scope=SCOPE                 Use this Netbios scope
  -W, --workgroup=WORKGROUP                 Set the workgroup name
      --realm=REALM                         Set the realm name
```
### Output
The output from `nmblookup` includes tags which tell you what type of service each found service is. 
![](CLI-tools/CLI-tools-pics/nmblookup-1.png)
> [Hacking Articles](https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/)

In the above image, the tag `<00>` next to `DESKTOP-ANTONJ9` tells us that the service is a *Workstation Service* (Workgroup/ domain name). Other tags include:
- `<03>` Windows Messenger service
- `<06>` Remote Access Service
- `<20>` File Service (also called *Host Record*)
- `<21>` Remote Access Service Client
- `<1B>` Domain Master Browser (the primary [Domain Controller](/networking/DNS/domain-controller.md) for a domain)
- `<1D>` Master Browser
- `<1C>` Domain Controllers for a domain
- `<1E>` Browser Service Elections
### Useful options:
```bash
nmblookup -A <target IP>
```
#### `-A`: Lookup via IP
This tells `nmblookup` to interpret the name as an IP address. It then does a *node status query* on the provided address to find NetBIOS names associated w/ the provided IP address.
##### Node Status Query:
A *node status query* is a query which returns the NetBIOS names registered by a host.
#### `-T`: Translate
This causes an IP addresses found during the query to be looked up using a *reverse DNS lookup* so it can be resolved into a DNS name as well. `nmblookup` will then return the regular `IP address .... NetBIOS name` pair, as well as the DNS name.
#### `-W`: WORKGROUP
Using this flag allows you to *override the default workgroup name* defined in the `smb.conf` & `/etc/samba/smb.conf` files.

> [!Resources]
> [Hacking Articles: ...SMB enumeration](https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/)
> - `man nmblookup`
