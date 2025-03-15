
# tcpdump Command
Init.
## Useful Options
### List Network interfaces `-D`
```bash
# tcpdump -D
1.eth0 [Up, Running, Connected]
2.tailscale0 [Up, Running, Connected]
3.any (Pseudo-device that captures on all interfaces) [Up, Running]
4.lo [Up, Running, Loopback]
5.docker0 [Up, Disconnected]
6.bluetooth-monitor (Bluetooth Linux Monitor) [Wireless]
7.nflog (Linux netfilter log (NFLOG) interface) [none]
8.nfqueue (Linux netfilter queue (NFQUEUE) interface) [none]
9.dbus-system (D-Bus system bus) [none]
10.dbus-session (D-Bus session bus) [none]
```
### Listen for source ip `host`
```bash
tcpdump -i eth0 host 192.168.5.5
```
### Packet content `-A`
