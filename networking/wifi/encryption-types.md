
# Types of WiFi Networks by Encryption
## Types
### Open Authentication (OPN)
In OPN networks, there are *no authentication requirements for users connecting to the network*. The network is open, meaning anyone can connect to it w/o a password. Because there is *no encryption* provided by the network, traffic intercepted on the network can be read in plaintext. Some OPN networks include a *captive portal* which is a web page where users are redirected to before accessing the internet. 
### Opportunistic Wireless Encryption (OWE)
A more secure alternative to OPN, OWE offers encryption *without needing a shared password*.
### Wired Equivalent Privacy (WEP)
One of the first protocols introduced for wireless networks. It works by using a pre-shared password b/w clients and the AP. The password only needs to be 10 characters long and in hexadecimal format. The password can be cracked very easily.
### Pre-Shared Key (PSK)
PSK is a security mode used w/ WPA and WPA2 to authenticate clients. A password is set on the AP and then and device wishing to connect has to provide the password. The overall security of a PSK network *depends on the complexity of the key* and who its been shared with. Having the key allows a user (or attacker) to decrypt traffic on the network.
### Simultaneous Authentication of Equals (SAE)
SAE is primarily a key component of WPA3, which is the latest security certification for [WiFi](802.11.md). SAE improves on PSK by using a more complex *handshake process* which makes brute-force and dictionary attacks against the password much more difficult.
### WPA2/WPA3 Transitional
This is a hybrid mode used in networks which are transitioning wireless networks from WPA2 to WPA 3. It allows *older devices which can't support WPA3 to connect to a WPA3 network*. 
### WPA/WPA2/WPA3-Enterprise (MGT)
MGT (which stands for management) is a version of WPA designed for corporate/enterprise environments. For authentication, this method integrates with a server-based auth system like a *RADIUS server* to manage user access (rather than a PSK system). 

Rather than using a shared key (like a password) users authenticate *individually* based on unique credentials (either a username and password or a *digital certificate*). This significantly improves the network's security because if a single user's credentials are compromised *their access can be revoked*.

This mode also includes [MFP](802.11.md#802.11w%20(MFP)) (Management Frame Protection) (?), which also greatly improves its security. Unfortunately, deploying and managing transitional networks is difficult and so it is less common in corporate networks.

> [!Resources]
> - [WiFiChallenge Academy](https://academy.wifichallenge.com/)

