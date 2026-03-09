---
aliases:
  - karma attack
---
# Karma Attack
When a client device has connected to a network before, the network is added to the devices *"Preferred Network" list*. The device then actively probes for the SSIDs in the list, even if that network *isn't nearby*. The karma attack takes advantage of this by responding with any requested SSID.

When the client associates to the malicious AP, this gives the attacker the ability to intercept traffic and perform machine-in-the-middle attacks. However, this attack *only works on OPN networks*. On a PSK network, the attacking device will only receive half a handshake.
## How it Works
- **Client Probe Requests**: client devices periodically broadcast probe requests for SSIDs of network they've connected to before
- **Rogue AP Response**: the attacker's AP listens for the probe requests and immediately responds by impersonating the requested SSID
- **Automatic Association**: the client associates to the rogue AP
- **Traffic Capture/ Injection**: all client traffic transmits through the AP, allowing the attacker to perform *packet sniffing and manipulation*
## Example with `eaphammer`
[`eaphammer`](https://github.com/s0lst1c3/eaphammer) is a tool primarily used for [evil twin](../PSK-attacks/evil-twin.md) attacks on PSK networks, but can also be used for karma attacks on OPNs. To launch a karma attack:
```bash
./eaphammer -i wlan0 --essid <AP ESSID> --cloaking full -c 1 --auth open --karma
```
- `i`: attacking interface
- `--essid`: specify the ESSID of the AP
- `--cloaking`: use SSID cloaking, i.e.: send empty SSID beacons and ignore request frames which don't specify a full SSID (options are 'none' or 'full' or 'zeroes')
- `-c`: specify the channel
- `--auth`: specify the auth type (OPN in this case)
- `--karma`: enable karma attacks


> [!Resources]
> - [GitHub - s0lst1c3/eaphammer: Targeted evil twin attacks against WPA2-Enterprise networks. Indirect wireless pivots using hostile portal attacks. · GitHub](https://github.com/s0lst1c3/eaphammer)