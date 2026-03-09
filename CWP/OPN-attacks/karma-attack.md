---
aliases:
  - karma attack
---
# Karma Attack
When a client device has connected to a network before, the network is added to the devices *"Preferred Network List* (PNL). The device then actively probes for the SSIDs in the list, even if that network *isn't nearby*. The karma attack takes advantage of this by responding with any requested SSID.

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
### Attack Sequence Example
First, we need to find a client with multiple probes. We can do that by starting the [Aircrack-ng](../../../cybersecurity/wifi/Aircrack-ng.md) suite:
#### 1. Put interface into monitor mode
Run the `airmon-ng` start command to put `wlan0` into monitor mode:
```bash
sudo airmon-ng start wlan0
```
#### 2. Start capturing traffic
Use `airodump-ng` to start capturing traffic and finding clients who are probing for other networks:
```bash
sudo airodump-ng --band bag --gpsd wlan0mon
```
Here, we see a client who is associated to one of the APs but is also probing for other networks (which aren't listed in the ESSID column):
![](../../CWP-pics/karma-attack-1.png)
We can also see that `eaphammer` has spawned an ESSID based on the clients' probe requests (green):
![](../../CWP-pics/karma-attack-2.png)
#### 3. Disassociate the client
Now we force the client to disassociate from `F0:9F:C2:71:22:17` ("wifi-global") using `aireplay-ng`:
```bash
aireplay-ng -0 0 -a F0:9F:C2:71:22:17 -c 64:32:A8:BC:53:51 wlan0mon
```
> [!Note]
> For some reason, aireplay-ng will start the deauth on a random (?) channel (or on the channel `wlan0mon` is currently scanning on). Unfortunately, it *has to deauth on the same channel* as the target AP (in this case 44). I had to run it multiple times until it decided to use channel 44.
>
> Alternatively, you can stop `airodump-ng` then re-run it with the `--channel` flag (set to 44 in this case), but you will lose insight on other channels
> 

#### 4. Check for reassociation
If disassociation worked, you should see on `eaphammer` that the client reassociated to your rogue AP. The output should look like this:
![](../../CWP-pics/karma-attack-3.png)


> [!Resources]
> - [GitHub - s0lst1c3/eaphammer: Targeted evil twin attacks against WPA2-Enterprise networks. Indirect wireless pivots using hostile portal attacks. · GitHub](https://github.com/s0lst1c3/eaphammer)
> - [Wifi Challenge Academy](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442980-introduction)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.
