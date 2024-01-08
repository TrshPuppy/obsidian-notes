
# Gobuster
Gobuster is a tool used to brute-force URIs including directories and files as well as [DNS](/networking/DNS/DNS.md) subdomains. It does so by enumerating hidden directories and files.
## Usage:
```
gobuster <mode> [OPTIONS]
```
example:
```
gobuster dir -u <IP Address> -w <path to wordlist>
This example scans an IP address for directory busting using a wordlist
```
### Modes:
#### `dir`: directory enumeration
Enumerate directories/ files branching off the target URL. Also includes hidden directories/ files.
- can use `-u` to specify a target domain/ IP
- use `-w` to specify the path to the wordlist you want to use to enumerate directory/ file names 
#### `vhost`: enumerate virtual hosts
When companies etc. host multiple domain names on a single server or cluster of servers it's called *virtual host routing*.
- one server is able to share data and resources with the other hostnames 
- Each subdomain may even have its own [IP address](/networking/OSI/IP-addresses.md).
##### Command Line Syntax:
```shell
gobuster vhost -w /usr/share/wordlists/seclists/subdomains-top1million-5000.txt -u http://thetoppers.htb
```
Gobuster will use the vhost in `-u` and append the words supplied by the wordlist like this:
```
Host: [word].thetoppers.htb
```
Then Gobuster will send an HTTP request to each enumerated subdomain w/ a host header that includes the host domain.
#### `dns`: enumerating subdomains
- use `-d` to specify a target domain you want to find a #subdomain in
- `-w` for a wordlist
- *May have to resolve domain name in /etc/hosts*
### Syntax: 
#### *help*: `gobuster -h` or `gobuster <mode> -h`
#### `-o <output string>` output
File to save output to.
#### `-v` verbose
#### `-x <file extension>` 
Tells gobuster to find/ try specific file types. For example, if you want it to find php pages, the command will look like:
```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u $t -x php
```
**NOTE:** you can list multiple file types: `-x php,html`
### Tips:
- To get a list of options specific to a mode use `gobuster <mode> -h`
- Gobuster is written in [golang](/coding/languages/golang.md) which makes it faster than similar tools
- **Disadvantage:** Can't do recursive enumeration (if you want to enumerate on directories below the outer directory, you have to run it again with the next directory deep as the target)

> [!Resources]
> - [Gobuster Homepage Kali Linux](https://www.kali.org/tools/gobuster/)
> - [Hack the Box Tier One Starting Point Box "Three"](https://app.hackthebox.com/starting-point)