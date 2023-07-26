
# [Kioptrix](https://www.vulnhub.com/series/kioptrix,8/)
Kioptrix is a vulnerable VM you can download from [VulnHub](https://www.vulnhub.com).

## nmap scanning:
[nmap](/CLI-tools/linux/nmap.md) is a network scanning tool which scans a target IP address for open ports.

### `-sS` ("Stealth" scanning):
This technique *is not stealthy* like it used to be, but is still called a "stealth scan" in nmap. 

This scan sends a `SYN` packet to all the ports on the target address (under the first 1000 if a port range isn't given). If the port responds with `ACK` (like it should for a [TCP](/networking/protocols/TCP.md) 3 way handshake), then nmap closes the connection *without finishing the handshake*, thus making it "stealthy".

Ports which respond with `ACK` are reported by nmap as "open."

### Other options:
#### `-T` Timing:
The `-T` flag allows you to tell nmap how fast you want the scan to be done. You can give it a number between 0 and 5 with 5 being the fastest.

Higher/ faster settings will be less accurate. Slower settings will be *more accurate* and *harder to detect* (not sure on this check [Nmap: Timing and Performance](https://www.twitch.tv/melkey)).

#### `-p` Ports:
You can use the `-p` flag to tell nmap which ports you want it to scan. If you don't give this flag, then nmap *will scan the first 1000* which are generally assigned to specific services.

To scan all the ports use `nmap -p-`.

#### `-A` All:
The `-A` flag tells nmap to *scan using all of the detection options* which including versioning `-sV`, OS detection `-O`, script scanning `-sC`, and [traceroute](/CLI-tools/linux/traceroute.md) `--traceroute`.

































> [!Resources]
> - [Nmap.org](https://nmap.org)
> - [hummus-ful: Kioptrix Walkthrough](https://hummus-ful.github.io/vulnhub/2021/01/17/Kioptrix_1.html)