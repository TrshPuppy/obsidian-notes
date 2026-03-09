# Creating Wi-Fi Networks
## `hostapd`
The `hostapd` configuration file is used to define settings for a Wi-Fi access point or authentication server. It allows customization of several crucial parameters for setting up and managing wireless networks. Here is a brief overview of some key parameters:
- **interface**: Specifies the wireless network interface, such as wlan0
- **bridge**: Defines if the interface is part of a network bridge, useful for linked devices
- **driver**: Indicates the type of interface driver, for example, `nl80211` for modern Linux systems
- **ssid**: Specifies the network name
- **hw_mode and channel**: Determine the wireless protocol (a/b/g/n/ac) and the channel number
- **macaddr_acl**: Manages MAC address filtering for device connectivity
- **auth_algs:** Specifies the authentication algorithms used, often necessary for WPA/WPA2
- **ignore_broadcast_ssid**: Can hide the SSID to prevent it from appearing in public listings
- **wpa**: Configures WPA/WPA2 encryption
- **wpa_passphrase/wpa_key_mgmt:** Sets the network passphrase and key management protocol
- **wpa_pairwise andrsn_pairwise**: Define pairwise ciphers for encryption
- **country_code:** Sets the country code to comply with regional wireless transmission regulations
### Advanced Configurations
- **ieee80211n**: Enables or disables support for [802.11](../../networking/wifi/802.11.md)n features (High Throughput)
- **ieee80211ac**: Enables or disables support for 802.11ac features (Very High Throughput)
- **ieee80211ax**: Enables or disables support for 802.11ax (Wi-Fi 6) for better efficiency
- **ht_capab**: Configures specific 802.11n HT capabilities such as HT40+, HT40-
- **vht_capab**: Configures VHT capabilities of 802.11ac such as supported channel widths and modulation
### Security Enhancements
- **ieee80211w**: Configures [Management Frame Protection (MFP)](../../networking/wifi/802.11.md#802.11w%20(MFP)) , which can be disabled, optional, or required, enhancing security against deauthentication attacks
- **wpa_group_rekey**: Sets how often the Group Temporal Key (GTK) is rotated to improve security. The GTK is a shared key in a Wi-Fi network that encrypts broadcast and multicast traffic between connected devices
- **wpa_strict_rekey**: Forces a rekey each time a client leaves the network, reducing the risk of old keys being used maliciously
### Compatibility and Compliance
- **ieee80211d**: Enables global compliance with spectrum management regulations
- **ieee80211h**: Enables radar detection and dynamic frequency selection, which is mandatory in some countries for operation in the 5 GHz band
## Usage Examples[](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442984-creating-wi-fi-networks-access-points#usage-examples)
Below are examples of each type of network for hostapd.
### OPN Network[](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442984-creating-wi-fi-networks-access-points#opn-network)
```
interface=wlan0
driver=nl80211
hw_mode=g
channel=6
ssid=OpenNetwork
wpa=0
# MAC Filter
#macaddr_acl=1
#accept_mac_file=/root/open/acceptMac.txt
ap_isolate=1
```
- `interface`: Specifies the wireless interface to be used
- `driver`: Indicates the driver used to manage the wireless interface
- `hw_mode`: Defines the hardware mode (e.g., ‘g' for 2.4 GHz)
- `channel`: The channel on which the wireless network will operate (e.g., 6)
- `ssid`: The name of the wireless network
- `wpa`: Sets the security protocol (0 for no encryption, open)
- `macaddr_acl`: Specifies MAC address access control (optional and commented out)
- `accept_mac_file`: File with the list of allowed MAC addresses (optional and commented out)
- `ap_isolate`: Isolates clients connected to the access point, preventing them from communicating with each other
### OWE Network[](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442984-creating-wi-fi-networks-access-points#owe-network)
```
interface=wlan0
driver=nl80211
ssid=MyOWENetwork
hw_mode=g
channel=6
ieee80211w=1
wpa=2
wpa_key_mgmt=OWE
rsn_pairwise=CCMP
```
- `ieee80211w`: Enables protected management frames (1 enabled)
- `wpa`: Sets the security protocol (2 for WPA2)
- `wpa_key_mgmt`: WPA key management method (OWE for Opportunistic Wireless Encryption)
- `rsn_pairwise`: Cipher used for the network (CCMP)
### WEP Network[](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442984-creating-wi-fi-networks-access-points#wep-network)
```
interface=wlan0
driver=nl80211
#ignore_broadcast_ssid=2
hw_mode=g
channel=1
ssid=wifi-old
auth_algs=1
wep_default_key=0
wep_key0=1122334455
```
- `ignore_broadcast_ssid`: Controls whether the SSID is broadcast in beacon frames (optional and commented out)
- `auth_algs`: Authentication algorithm (1 for open system)
- `wep_default_key`: Default WEP key
- `wep_key0`: Value of the WEP key (first index, usually 0)
### PSK Network[](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442984-creating-wi-fi-networks-access-points#psk-network)
```
interface=wlan0
driver=nl80211
hw_mode=g
channel=6
ssid=wifi-mobile
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
wpa_passphrase=passwordPSK
```
- `wpa_key_mgmt`: WPA key management method (WPA-PSK for Pre-Shared Key).
- `wpa_pairwise`: Indicates encryption methods (TKIP and CCMP).
- `wpa_passphrase`: Pre-shared passphrase.
### SAE Network[](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442984-creating-wi-fi-networks-access-points#sae-network)
```
interface=wlan0
ctrl_interface=/var/run/hostapd
ssid=wifi-management
hw_mode=g
channel=11
wmm_enabled=1
wpa=2
wpa_passphrase=passwordSAE
wpa_key_mgmt=SAE
ieee80211w=2
```
- `ctrl_interface`: Path to the control directory
- `wmm_enabled`: Enables Wi-Fi Multimedia (WMM)
- `wpa_key_mgmt`: WPA key management method (SAE for Simultaneous Authentication of Equals)
- `ieee80211w`: Enables protected management frames (2 for required)
### MGT Network[](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442984-creating-wi-fi-networks-access-points#mgt-network)
In MGT networks, not only is the `hostapd` configuration file necessary, but you also need a TLS certificate and a file with user credentials or a connection to a Radius server.
```
interface=wlan0
ssid=wifi-corp
channel=44
hw_mode=a
country_code=ES
ieee8021x=1
ieee80211d=1
wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP
rsn_pairwise=CCMP
eap_server=1
eapol_key_index_workaround=0
own_ip_addr=127.0.0.1
eap_user_file=/root/mgt/hostapd_wpe.eap_user
ca_cert=/root/mgt/certs/ca.crt
server_cert=/root/mgt/certs/server.crt
private_key=/root/mgt/certs/server.key
private_key_passwd=whatever
```
- `country_code`: Country code to set regulations
- `ieee8021x`: Enables IEEE 802.1X for network authentication
- `ieee80211d`: Enables IEEE 802.11d (announcement of local regulations)
- `wpa_key_mgmt`: WPA key management method (WPA-EAP for EAP-based authentication)
- `eap_server`: Enables the internal EAP server
- `eapol_key_index_workaround`: Parameter related to EAPOL key management
- `own_ip_addr`: IP address of the access point
- `eap_user_file`: EAP user configuration file
- `ca_cert`: Path to the certificate of the certification authority
- `server_cert`: Path to the server certificate
- `private_key`: Path to the server's private key
- `private_key_passwd`: Password for the private key

Once the `hostapd` file is created, you need to create an eap_user configuration file for `hostapd`. This file is specified in the path `/root/mgt/hostapd_wpe.eap_user` within the `hostapd` file.
```
# Phase 1 users
"example user"	TLS
"DOMAIN\user"	MSCHAPV2	"password"
# Phase 2 (tunnelled within EAP-PEAP or EAP-TTLS) users
"DOMAIN\t-mschapv2"	MSCHAPV2	      "password"	[2]
"t-gtc"		     GTC	            "password"	[2]
"user"		     MD5,GTC,MSCHAPV2	 "password"	[2]
"test user"	     MSCHAPV2	      hash:000102030405060708090a0b0c0d0e0f	[2]
```
- **Phase 1 Users:**
    - "example user" uses EAP-TLS, which relies on certificates instead of a password
    - "DOMAIN\user" uses EAP-MSCHAPv2 with the password "password"
- **Phase 2 Users (tunnelled within EAP-PEAP or EAP-TTLS):**
    - "DOMAIN\t-mschapv2" uses EAP-MSCHAPv2 with the password "password," specifically for Phase 2
    - "t-gtc" uses EAP-GTC with the password "password" in Phase 2
    - "user" can authenticate using EAP-MD5, EAP-GTC, or EAP-MSCHAPv2 with the password "password" in Phase 2
    - "test user" uses EAP-MSCHAPv2 with a hashed password in Phase 2
Phase 1 entries handle initial authentication, while Phase 2 entries are used within an encrypted tunnel for secure authentication. For example, 'DOMAIN\t-mschapv2' would be used within an EAP-PEAP or EAP-TTLS tunnel (Phase 2), while 'DOMAIN\user' would be used without an encrypted tunnel (Phase 1).

You can use openssl to generate the necessary configuration files for TLS. To automate this process, you can use hostapd-wpe or a bash script like the following to generate everything.
```
#!/bin/bash

# Variables
ESSID="YourSSID"
CA_DIR=~/hostapd_certs
OPENSSL_CNF=$CA_DIR/openssl.cnf
HOSTAPD_CONF=/etc/hostapd/hostapd.conf

# Create directory for certificates
mkdir -p $CA_DIR
cd $CA_DIR

# Create OpenSSL configuration file
cat > $OPENSSL_CNF < serial

# Generate CA certificate
openssl req -new -x509 -extensions v3_ca -keyout private/cakey.pem -out cacert.pem -config $OPENSSL_CNF -days 3650

# Generate server key and certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -config $OPENSSL_CNF
openssl ca -batch -keyfile private/cakey.pem -cert cacert.pem -in server.csr -out server.pem -config $OPENSSL_CNF -extensions v3_req

# Optional: Generate client key and certificate
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -config $OPENSSL_CNF
openssl ca -batch -keyfile private/cakey.pem -cert cacert.pem -in client.csr -out client.pem -config $OPENSSL_CNF -extensions v3_req

# Configure hostapd
sudo bash -c "cat > $HOSTAPD_CONF <<EOL
interface=wlan0
driver=nl80211
ssid=$ESSID
hw_mode=g
channel=6
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP

ieee8021x=1
eapol_version=2
eap_server=0
ca_cert=$CA_DIR/cacert.pem
server_cert=$CA_DIR/server.pem
private_key=$CA_DIR/server.key
EOL"

# Restart hostapd
sudo systemctl restart hostapd

echo "Certificates generated and hostapd configured successfully."
```
The script does the following:
- Create necessary directories and files to store certificates and keys
- Generate the root certificate for the CA
- Generate the private key and certificate for the server
- Optional: Generate the private key and certificate for the client
- Configure hostapd with the generated certificates and restart the service to apply the changes
#### Explanation of each entry in the OpenSSL configuration file:
##### ca
Defines the configuration section for CA operations
- `default_ca` = CA_default: Defines the default CA configuration
##### CA_default
Default CA settings
- `dir = $CA_DIR`: Directory where files will be stored
- `database = \$dir/index.txt`: File that maintains an index of issued certificates
- `new_certs_dir = \$dir/newcerts`: Directory where newly issued certificates will be stored
- `certificate = \$dir/cacert.pem`: Location of the CA certificate
- `serial = \$dir/serial`: File that contains the serial number of the next certificate to be issued
- `private_key = \$dir/private/cakey.pem`: Location of the CA's private key
- `default_days = 365`: Default duration of issued certificates
- `default_md = sha256`: Default hash algorithm for the CA
- `preserve = no`: Do not preserve policy names
- `policy = policy_anything`: Policy used to verify certificate information
##### policy_anything
Defines the name policy. The following configurations are optional:
- `countryName`
- `stateOrProvinceName`
- `localityName`
- `organizationName`
- `organizationalUnitName`
- `commonName`
- `emailAddress`
##### req
Configuration for certificate requests.
- `default_bits = 2048`: Default key size
- `prompt = no`: Disables prompts during certificate generation
- `default_md = sha256`: Default hash algorithm for the request
- `distinguished_name = req_distinguished_name`: Section that defines the Distinguished Name (DN)
##### req_distinguished_name
Defines the DN for certificate requests
- C: Country (U.S. in this example)
- ST: State (California)
- L: Locality (San Francisco)
- O: Organization (MyCompany)
- OU: Organizational Unit (MyDepartment)
- CN: Common Name (MyAP)
##### v3_ca
Extensions applicable to the CA certificate.
- `subjectKeyIdentifier=hash`: Key identifier.
- `authorityKeyIdentifier=keyid:always,issuer`: Authority identifier
- `basicConstraints = CA:true`: Defines that this certificate can act as a CA
##### v3_req
Extensions applicable to certificate requests
- `keyUsage = nonRepudiation, digitalSignature, keyEncipherment`: Key usage
- `extendedKeyUsage = serverAuth, clientAuth`: Extended key usage

> [!Resources]
> - [Wifi Challenge Academy](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442980-introduction)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.