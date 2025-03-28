
# A list of recon sources on Linux Targets
## Network
### `/etc/network/interfaces`
File which can include cleartext passwords for logging into network interfaces including WiFi:
```bash
auto wlan0
iface wlan0 inet static
address 192.168.1.150
netmask 255.255.255.0
gateway 192.168.1.1
wpa-essid mywifiname
wpa-psk mypass
```
> [!Resource]
> - [LinuxConfig: etcnetworkinterface](https://linuxconfig.org/etcnetworkinterfacesto-connect-ubuntu-to-a-wireless-network)

### `/etc/netplan`
Similar to `/etc/network/interfaces`. Contains network [YAML](../../../../coding/markup/YAML.md) config files sometimes w/ cleartext passwords.
