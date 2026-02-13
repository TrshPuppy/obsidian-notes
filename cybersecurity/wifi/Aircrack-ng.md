# Aircrack-ng
[Aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) it a suite of tools used for [wifi](../../networking/wifi/802.11.md) security testing. It focuses on 4 areas of testing:
- **Monitoring**: Capturing packets and saving them to files so they can be processed and analyzed by other tools
- **Attacking**: Replay attacks, deauthentication, fake access point and packet injection
- **Testing**: Checking wifi card driver capabilities
- **Cracking**:  WEP and WPA PSK (WPA 1 and 2)
## Six Most Common Tools
Within the aircrack suite, there are over 20 tools, but the most commonly used in pentesting are the following:
- **Airmon-ng**: Enable and disable monitor mode on an interface
- **Airodump-ng**: Capture raw [802.11](../../networking/wifi/802.11.md) frames
- **Airgraph-ng**: Create graphs of wireless networks via the CSV files created by Airodrop
- **Aireplay-ng**: Generate wireless traffic
- **Airdecap-ng**: decrypt WEP, WPA and WPA2 PSK capture files
- **Aircrack-ng**: crack WEP and WPA/WPA2 PSKs or PMKID
## Airmon-ng
Airmon-ng can be used to enable [Monitor Mode](interface-modes.md#Monitor%20Mode) on an interface. It can also be used to kill network managers or return from monitor mode to managed mode. Running the `airmon-ng` command with no flags will show the interface's name, chipset and driver:
```bash
trshpuppy@htb[/htb]# sudo airmon-ng

PHY     Interface       Driver          Chipset

phy0    wlan0           rt2800usb       Ralink Technology, Corp. RT2870/RT3070
```
### Starting Monitor Mode
To put the interface into monitor mode, you can use the following `airmon-ng` command:
```bash
trshpuppy@htb[/htb]# sudo airmon-ng start wlan0

Found 2 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    559 NetworkManager
    798 wpa_supplicant

PHY     Interface       Driver          Chipset

phy0    wlan0           rt2800usb       Ralink Technology, Corp. RT2870/RT3070
                (mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)
                (mac80211 station mode vif disabled for [phy0]wlan0)
```
### Check for Interfering Processes
Usually when you put an interface into monitor mode, it will automatically check for interfering processes, but you can also check manually with the `check` flag:
```bash
trshpuppy@htb[/htb]# sudo airmon-ng check

Found 5 processes that could cause trouble.
If airodump-ng, aireplay-ng or airtun-ng stops working after
a short period of time, you may want to kill (some of) them!

  PID Name
  718 NetworkManager
  870 dhclient
 1104 avahi-daemon
 1105 avahi-daemon
 1115 wpa_supplicant
```
The processes in the output can cause issues because they may *change channels or put the interface back into managed mode*. Fortunately `airmon-ng` has a kill command we can use if that happens:
```bash
trshpuppy@htb[/htb]# sudo airmon-ng check kill

Killing these processes:

  PID Name
  870 dhclient
 1115 wpa_supplicant
```
### Starting Monitor Mode on Specific Channel
```bash
trshpuppy@htb[/htb]# sudo airmon-ng start wlan0 11

Found 5 processes that could cause trouble.
If airodump-ng, aireplay-ng or airtun-ng stops working after
a short period of time, you may want to kill (some of) them!

  PID Name
  718 NetworkManager
  870 dhclient
 1104 avahi-daemon
 1105 avahi-daemon
 1115 wpa_supplicant

PHY     Interface       Driver          Chipset

phy0    wlan0           rt2800usb       Ralink Technology, Corp. RT2870/RT3070
                (mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)
                (mac80211 station mode vif disabled for [phy0]wlan0)
```
### Stopping Monitor Mode
```bash
trshpuppy@htb[/htb]# sudo airmon-ng stop wlan0mon

PHY     Interface       Driver          Chipset

phy0    wlan0mon        rt2800usb       Ralink Technology, Corp. RT2870/RT3070
                (mac80211 station mode vif enabled on [phy0]wlan0)
                (mac80211 monitor mode vif disabled for [phy0]wlan0)
```
## Airodump-ng
The Airodump tool is used for capturing 802.11 frames, specifically WEP IVs (Initialization Vectors) and WPA/WPA2 handshakes. `airodump-ng` generates multiple files containing info on all of the identified access points. To use airodump, the interface should be *in monitor mode*.
### Fields
The output from an `airodump-ng` command will include:

| **Field** | **Description**                                                                          |
| --------- | ---------------------------------------------------------------------------------------- |
| `BSSID`   | Shows the MAC address of the access points                                               |
| `PWR`     | Shows the "power" of the network. The higher the number, the better the signal strength. |
| `Beacons` | Shows the number of announcement packets sent by the network.                            |
| `#Data`   | Shows the number of captured data packets.                                               |
| `#/s`     | Shows the number of data packets captured in the past ten seconds.                       |
| `CH`      | Shows the "Channel" the network runs on.                                                 |
| `MB`      | Shows the maximum speed supported by the network.                                        |
| `ENC`     | Shows the encryption method used by the network.                                         |
| `CIPHER`  | Shows the cipher used by the network.                                                    |
| `AUTH`    | Shows the authentication used by the network.                                            |
| `ESSID`   | Shows the name of the network.                                                           |
| `STATION` | Shows the MAC address of the client connected to the network.                            |
| `RATE`    | Shows the data transfer rate between the client and the access point.                    |
| `LOST`    | Shows the number of data packets lost.                                                   |
| `Packets` | Shows the number of data packets sent by the client.                                     |
| `Notes`   | Shows additional information about the client, such as captured EAPOL or PMKID.          |
| `PROBES`  | Shows the list of networks the client is probing for.                                    |
### Get an Inventory
Gets a list of all active SSIDs the card can see (in monitor mode). Should run this about 5 minutes to get a good idea of all of the APs active on the network. The output will also tells you what authentication type each SSID is using.
```bash
airodump-ng wlan0 --band abg -w <client>_<location>_SSIDinventory
```


> [!References]
> - [Aircrack-ng](https://github.com/aircrack-ng/aircrack-ng)
> - [HTB Academy](https://academy.hackthebox.com/module/222/section/2922)