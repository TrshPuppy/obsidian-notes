# Managing Wi-Fi Interfaces on Linux
Managing [wifi](../../networking/wifi/802.11.md) interfaces involves enabling or disabling them, changing their power settings, and putting them into one of the different modes they support.
## Enable and Disable an Interface
Enabling:
```bash
sudo ip link set dev wlan0 up
```
Disabling:
```bash
sudo ip link set dev wlan0 down
```
## Scanning Wi-Fi Networks
After *ensuring the interface is active* (see above) you can use the `iw` command to scan for reachable wi-fi networks:
```bash
sudo iw dev wlan0 scan
```
This command will list all available wifi networks as well as detailed info including SSID, signal strength, encryption type, etc..
### `nmcli`
You can also use NeworkManager's `nmcli` command:
```bash
nmcli dev wifi list
```
- Lists all wifi networks
```bash
nmcli dev wifi connect <SSID_NAME> password <PASSWORD>
```
- Connect to a specific wifi network from the cli
### Other Useful Commands:
- `iw dev` or `ip link show wlan0`: show configuration status for a wireless device
- `ip link set wlan0 up`: enable a wifi interface
- `iw wlan0 link`: check the link status
- `iw wlan0 scan`: start a direct scan of access points
- `iw wlan0 scan | grep <SSID>`: show only a specific SSID from the output
- `iw dev wlan0 scan | grep "^BSS\|SSID\|WSP\|Authentication\|WPA"`: detailed scan results including BSSID, SSID, and security protocols
## Manually Configure Interface on Specific Channel
```bash
iwconfig wlan0mon channel 11
```
## Monitor Mode
Monitor mode allows the interface to capture *all traffic* on a network, not just traffic destined for it.
### Steps
#### 1. Disable Network Manager
This will prevent it from interfering w/ the interface: 
```bash
sudo systemctl stop NetworkManager
```
On other linux distros, the command will vary:
```bash
# wifislax
service stop networkmanager

# Suse, Fedora, Gentoo, CentOS
service NetworkManager stop

# Pentoo
rc-service NetworkManager stop
```
Some even older systems use the networking service instead of NetworkManager:
```bash
# systemd
sudo systemctl stop networking

# SysVinit
sudo service networking stop
```
In some lightweight distributions, there is also `wicd`
```bash 
# systemd
sudo systemctl stop wicd

# SysVinit
sudo service wicd stop
```
##### Temporarily Excluding an Interface
Instead of disabling the service managing your network, you can temporarily exclude specific interfaces using the `nmcli` command:
```bash
sudo nmcli dev set <interface_name> managed no
```
To re-enable it:
```bash
sudo nmcli dev set <interface_name> managed yes
```
#### 2. Enable Monitor Mode
```bash
sudo ip link set wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ip link set wlan0 up
```
#### 3. Verify
Use the `iwconfig` command by itself. In the output, you should see `Mode:Monitor`.
#### 4. Disable Monitor Mode
```bash
sudo ip link set wlan0 down 
sudo iwconfig wlan0 mode managed 
sudo ip link set wlan0 up 
```
### Capturing Packets with `tcpdump`
Once in monitor mode, you can use tcpdump to capture packets on the interface and save the output to a specific file:
```bash
sudo tcpdump -i wlan0mon -w /path/to/file.cap
```
## Change MAC Address
Useful for providing anonymity or evading [MAC](../../networking/OSI/2-datalink/MAC-addresses.md)-based security configurations.
### Steps
#### 1. Disable interface
```bash
sudo ifconfig wlan0 down
```
#### 2. Change the MAC
There are a few ways you can change the MAC. You can change it using the `ip` command:
```bash
ip link set wlan0 down
ip link set dev wlan0 address 00:11:22:33:44:55
ip link set wlan0 up
```
You can generate a random MAC with `macchanger`:
```bash
sudo macchanger -r wlan0 
```
Or to  a specific one:
```bash
sudo macchanger -m 00:11:22:33:44:55 wlan0
```
Or you can use `ifconfig`:
```bash
sudo ifconfig wlan0 hw ether 00:11:22:33:44:55 # Sets a specific MAC address
```
#### 3. Re-enbale the Interface
```bash
sudo ifconfig wlan0 up
```

> [!Resources]
> - [Wifi Challenge Academy](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442980-introduction)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.
