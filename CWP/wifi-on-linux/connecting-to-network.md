# Connecting to Wi-Fi Network
For managing Wi-Fi networks on Linux, two popular tools are nmcli and wpa_supplicant. nmcli is a command-line client for NetworkManager and is suitable for quick tasks. On the other hand, wpa_supplicant provides greater control, especially useful for complex configurations.
## Open Networks (OPN)
### Using `nmcli`
```bash
nmcli device wifi connect SSID_NAME
```
### Using `wpa_supplicant`
#### 1. Create a configuration file named `wifi-opn.conf`:
```bash
network={
  ssid="SSID_NAME"
  key_mgmt=NONE
  scan_ssid=1
}
```
- `ssid`: Name of the wireless network you want to connect to
- `key_mgmt`: Key management type; NONE indicates no encryption
- `scan_ssid`: To find networks with hidden SSIDs, scan_ssid=1 can be used. This forces the system to search for and connect to networks that are not visible in the normal SSID scan
#### 2. Connect
```bash
sudo wpa_supplicant -i wlan0 -c wifi-opn.conf
```
## Opportunistic Wireless Encryption (OWE) Networks
### Using `wpa_supplicant`
#### 1. Create a configuration file named `wifi-owe.conf`:
```bash
network={
  ssid="SSID_NAME"
  key_mgmt=OWE
}
```
- `ssid`: Name of the wireless network you want to connect to
- `key_mgmt`: Key management type; for Opportunistic Wireless Encryption
#### 2. Connect
```bash
sudo wpa_supplicant -i wlan0 -c wifi-owe.conf
```
## WEP Networks (Wired Equivalent Privacy)
### Using `nmcli`
```bash
nmcli device wifi connect SSID_NAME password PASSWORD
```
### Using `wpa_supplicant`
#### 1. Create a configuration file named `wifi-wep.conf`:
```bash
network={
  ssid="SSID_NAME"
  key_mgmt=NONE
  wep_key0=PASSWORD
  wep_tx_keyidx=0
}
```
- `wep_key0`: WEP Key for the Network. Whenever the password is in hexadecimal format, it should be entered without quotes and without colons :. For example, a password like 00:11:22:33:44 should be written as: wep_key0=0011223344
- `wep_tx_keyidx`: WEP key index (usually 0)
#### 2. Connect
```bash
sudo wpa_supplicant -i wlan0 -c wifi-wep.conf
```
## WPA/WPA2 PSK (Pre-Shared Key) Networks[](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442983-connecting-to-wi-fi-networks#wpawpa2-psk-pre-shared-key-networks)
### Using nmcli[](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442983-connecting-to-wi-fi-networks#using-nmcli)
To connect:
```
nmcli device wifi connect SSID_NAME password PASSWORD
```
### Using wpa_supplicant[](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442983-connecting-to-wi-fi-networks#using-wpa_supplicant)
#### 1. Create a configuration file named `wifi-psk.conf`
```
network={
  ssid="SSID_NAME"
  psk="PASSWORD"
}
```
- `psk`: Pre-Shared Key for WPA/WPA2
#### 2. Connect using `wpa_supplicant`
```
sudo wpa_supplicant -i wlan0 -c wifi-psk.conf
```
## WPA3-SAE Networks[](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442983-connecting-to-wi-fi-networks#wpa3-sae-networks)
### Using nmcli[](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442983-connecting-to-wi-fi-networks#using-nmcli)
To connect:
```
nmcli device wifi connect SSID_NAME password PASSWORD
```
### Using wpa_supplicant[](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442983-connecting-to-wi-fi-networks#using-wpa_supplicant)
#### 1. Create a configuration file named `wifi-sae.conf`
```
network={
  ssid="SSID_NAME"
  psk="PASSWORD"
  key_mgmt=SAE
  ieee80211w=2
}
```
- `key_mgmt`: Key management, SAE for WPA3
#### 2. Connect using `wpa_supplicant`
```
sudo wpa_supplicant -i wlan0 -c wifi-sae.conf
```
## WPA/WPA2 Enterprise (MGT) Networks[](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442983-connecting-to-wi-fi-networks#wpawpa2-enterprise-mgt-networks)
For WPA/WPA2/WPA3-Enterprise, specific configuration is needed due to various authentication methods.
### Using nmcli[](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442983-connecting-to-wi-fi-networks#using-nmcli)
To connect:
```
nmcli device wifi connect SSID_NAME password PASSWORD identity USERNAME eap PEAP phase2-auth MSCHAPV2
```
Replace USERNAME and PASSWORD with the necessary credentials.
### Using wpa_supplicant[](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442983-connecting-to-wi-fi-networks#using-wpa_supplicant)
#### 1. Create a configuration file named `wifi-mgt.conf`
```
network={
  ssid="SSID_NAME"
  key_mgmt=WPA-EAP
  eap=PEAP
  anonymous_identity="anonymous"
  identity="USERNAME"
  password="PASSWORD"
  phase2="auth=MSCHAPV2"
}
```
- `key_mgmt`: WPA-EAP key management for Enterprise
- `eap`: EAP authentication methods
- `anonymous_identity`: Anonymous identity
- `identity`: Username for authentication
- `password`: Password for authentication
- `phase2`: Second-phase authentication type, in this case, MS-CHAP v2 
#### 2. Connect using `wpa_supplicant`
```
sudo wpa_supplicant -i wlan0 -c wifi-mgt.conf
```
- Replace wlan0 with the necessary interface in each case
- wpa_supplicant requires root privileges for most operations
- Use -B with wpa_supplicant to run it in the background. Omit -B for foreground operation and more detailed output
- Ensure that your wpa_supplicant and NetworkManager are up to date to support newer protocols like WPA3-SAE and OWE
- If the ESSID is hidden, add hidden yes in the nmcli command
- wpa_supplicant can be run in the background with -B. In this mode, you can view logs with `sudo journalctl -u wpa_supplicant` or with `sudo grep wpa_supplicant /var/log/syslog`
## Managing Wireless Networks with WPA GUI in Ubuntu[](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442983-connecting-to-wi-fi-networks#managing-wireless-networks-with-wpa-gui-in-ubuntu)
WPA GUI offers an easy-to-use graphical interface for managing Wi-Fi connections in Ubuntu, eliminating the need for terminal commands.
### Installing WPA GUI[](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442983-connecting-to-wi-fi-networks#installing-wpa-gui)
```
sudo apt install wpa-gui
```
![](https://files.cdn.thinkific.com/file_uploads/937577/images/03f/5fb/51d/1737392803830.png?width=1920)
Launch WPA GUI:
```
wpa_gui 
```
or search for "WPA GUI" in the application menu
### WPA GUI Interface Overview[](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442983-connecting-to-wi-fi-networks#wpa-gui-interface-overview)
- **Current Status**
    - **Description:** Displays connected SSID, signal strength, and IP address.
- **Scan**
    - **Description:** Lists available networks with signal strength and encryption types
- **Network Configuration**
    - **Description:** Add, edit, or remove network profiles
- **Messages**
    - **Description:** Shows logs from wpa_supplicant for troubleshooting
### Connecting to a Wireless Network[](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442983-connecting-to-wi-fi-networks#connecting-to-a-wireless-network)
![](https://files.cdn.thinkific.com/file_uploads/937577/images/903/8b7/1bc/1737392816299.png?width=1920)

Scan with WPA GUI

![](https://files.cdn.thinkific.com/file_uploads/937577/images/a4a/21a/7bb/1737392820744.png?width=1920)

Add network wifi-guest

![](https://files.cdn.thinkific.com/file_uploads/937577/images/1c3/e31/b3e/1737392824603.png?width=1920)

Connect to the AP

![](https://files.cdn.thinkific.com/file_uploads/937577/images/27c/a11/a1f/1737392772590.png?width=1920)

Get IP once connected
- **Scan for Networks**
    - Navigate to the **Scan** tab and click **Scan**. Select your desired network
- **Configure the Network**
    - Double click a Network or go to **Network Configuration**, click **Add**, enter the SSID, choose security (e.g., WPA2), and input the password. Save the settings
- **Connect**
    - Return to **Current Status** and click **Connect** to join the network
- Get an IP
    - Once we are connected, we execute dhclient like always

> [!Resources]
> - [Wifi Challenge Academy](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442980-introduction)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.