
# RustScan
Init
## Usage
### Config File
Config file is saved in `/root/.rustscan.toml` and can be used to configure default scans (if you use them frequently and don't want to type them out everytime). 
#### Example Format
```toml
addresses = ["127.0.0.1", "192.168.0.0/30", "www.google.com"]
command = ["-A"]
ports = [80, 443, 8080]
range = { start = 1, end = 10 }
greppable = false
accessible = true
scan_order = "Serial"
batch_size = 1000
timeout = 1000
tries = 3
ulimit = 1000
```
## Examples which worked
### Basic
```bash
./rustscan -a <target IP or file>

┌─[25-03-17 16:59:14]:(root@192.168.144.131)-[/home/trshpuppy/oscp/recon]
└─# ./rustscan -a 192.168.210.52
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
You miss 100% of the ports you don't scan. - RustScan

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 192.168.210.52:22
Open 192.168.210.52:2222
Open 192.168.210.52:59811
[~] Starting Script(s)
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-17 17:00 EDT
Initiating Ping Scan at 17:00
Scanning 192.168.210.52 [4 ports]
Completed Ping Scan at 17:00, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 17:00
Completed Parallel DNS resolution of 1 host. at 17:00, 0.20s elapsed
DNS resolution of 1 IPs took 0.20s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 17:00
Scanning 192.168.210.52 [3 ports]
Discovered open port 22/tcp on 192.168.210.52
Discovered open port 2222/tcp on 192.168.210.52
Discovered open port 59811/tcp on 192.168.210.52
Completed SYN Stealth Scan at 17:00, 0.12s elapsed (3 total ports)
Nmap scan report for 192.168.210.52
Host is up, received echo-reply ttl 61 (0.10s latency).
Scanned at 2025-03-17 17:00:25 EDT for 0s

PORT      STATE SERVICE      REASON
22/tcp    open  ssh          syn-ack ttl 61
2222/tcp  open  EtherNetIP-1 syn-ack ttl 60
59811/tcp open  unknown      syn-ack ttl 60
```
### Running w/ Nmap flags
Type your RustScan command, then add `--` and add your [nmap](../../../../../CLI-tools/linux/remote/nmap.md) flags.
```bash
# ./rustscan -a 192.168.210.52 -p 59811 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 192.168.210.52:59811
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -A" on ip 192.168.210.52
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-17 17:04 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:04
Completed NSE at 17:04, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:04
Completed NSE at 17:04, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:04
Completed NSE at 17:04, 0.00s elapsed
Initiating Ping Scan at 17:04
Scanning 192.168.210.52 [4 ports]
Completed Ping Scan at 17:04, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 17:04
Completed Parallel DNS resolution of 1 host. at 17:04, 0.10s elapsed
DNS resolution of 1 IPs took 0.10s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 17:04
Scanning 192.168.210.52 [1 port]
Discovered open port 59811/tcp on 192.168.210.52
Completed SYN Stealth Scan at 17:04, 0.12s elapsed (1 total ports)
Initiating Service scan at 17:04
Scanning 1 service on 192.168.210.52
Completed Service scan at 17:04, 6.08s elapsed (1 service on 1 host)
Initiating OS detection (try #1) against 192.168.210.52
Retrying OS detection (try #2) against 192.168.210.52
Initiating Traceroute at 17:04
Completed Traceroute at 17:04, 0.11s elapsed
Initiating Parallel DNS resolution of 4 hosts. at 17:04
Completed Parallel DNS resolution of 4 hosts. at 17:04, 0.29s elapsed
DNS resolution of 4 IPs took 0.29s. Mode: Async [#: 1, OK: 0, NX: 4, DR: 0, SF: 0, TR: 4, CN: 0]
NSE: Script scanning 192.168.210.52.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:04
Completed NSE at 17:04, 0.21s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:04
Stats: 0:00:11 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE: Active NSE Script Threads: 1 (1 waiting)
NSE Timing: About 87.50% done; ETC: 17:04 (0:00:00 remaining)
Stats: 0:00:11 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE: Active NSE Script Threads: 1 (1 waiting)
NSE Timing: About 87.50% done; ETC: 17:04 (0:00:00 remaining)
Completed NSE at 17:04, 0.22s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:04
Completed NSE at 17:04, 0.00s elapsed
Nmap scan report for 192.168.210.52
Host is up, received echo-reply ttl 61 (0.099s latency).
Scanned at 2025-03-17 17:04:11 EDT for 11s

PORT      STATE SERVICE REASON         VERSION
59811/tcp open  unknown syn-ack ttl 60
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, Kerberos, NULL, RPCCheck, RTSPRequest, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServerCookie, X11Probe:
|     You found me. Great job!
|     Here is your flag:
|_    OS{7d7cf633ed1b1712b91fb1bbc7ff32e3}
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port59811-TCP:V=7.94SVN%I=7%D=3/17%Time=67D88E4C%P=aarch64-unknown-linu
SF:x-gnu%r(NULL,52,"You\x20found\x20me\.\x20Great\x20job!\nHere\x20is\x20y

..snip..
```
### Random Port Ordering
```bash
./rustscan -a 127.0.0.1 --range 1-1000 --scan-order "Random"
53,631
```



> [!Resources]
> - [GitHub](https://github.com/bee-san/RustScan)