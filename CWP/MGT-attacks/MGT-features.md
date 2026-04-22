# MGT Features & Functionalities

## Fast Roaming
Fast roaming, which is commonly used in enterprise/[MGT](../../networking/wifi/802.1X.md) WiFi networks, allows client devices to *quickly transition b/w APs w/o performing full authentication*. For this, protocols like `802.11r` are used which enable *key caching* and *pre-authentication* mechanisms.
#### Security Implications
Because fast roaming relies on stored keys and shortcut processes, it reduces the authentication overhead but also introduces potential attack vectors:
- **Key Reuse Risk:** Cached keys (like PMK) can be intercepted or replayed by an attacker if not properly protected
- **FT Handshake Attacks:** Attackers can attempt to manipulate or spoof FT requests to impersonate a legitimate AP or client
- **Weak PMKID Protection:** If the PMKID is exposed during fast transitions, it can be used in offline dictionary attacks, similar to those used in WPA2 cracking
- **Lack of Full Handshake:** Without a full handshake, mutual authentication and some verification steps may be skipped, making impersonation or MitM (Man-in-the-Middle) attacks more feasible
#### Attack with `hostapd`
Configure 802.11r to pre-authenticate and cache keys, drastically reducing association latency when clients roam between APs:
```bash
ieee80211r=1
mobility_domain=4f57     # Hex-encoded domain ID (two octets)
ft_over_ds=1             # Use Distribution System for FT
ft_psk_generate_local=1  # Generate local PSK for FT
r0_key_lifetime=10000    # Lifetime of R0 key in seconds
r1_key_holder=1
disable_pmksa_caching=0  # Keep PMKSA cache enabled
```
## Band Steering
Band steering encourages clients to *connect to 5GHz APs instead of 2.4GHz APs* which improves the network by reducing interference. The controller monitors client probe requests and signal metrics, then temporarily withholds responses on 2.4 GHz to "nudge" the client toward 5 GHz.
### Considerations
- **Reduced Congestion:** Offloads traffic from the crowded 2.4 GHz band
- **Improved Performance:** Clients on 5 GHz enjoy more non-overlapping channels and higher data rates
- **Compatibility Issues:** Some legacy devices may not follow steering hints and fall back to 2.4 GHz
- **Complexity:** Requires careful tuning of RSSI thresholds to avoid client flapping
## Airtime Fairness
Airtime fairness prevents slow or legacy clients from monopolizing the RF medium. Instead of sharing frames equally, *the AP allocates each client a time-based "slice,"* ensuring high-speed clients aren't slowed down by lower-rate devices.
### When to Enable
- **Mixed Client Speeds:** Scenarios with 802.11b/g and 802.11n/ac/ax devices operating simultaneously
- **High-Density Deployments:** Classrooms, auditoriums, or conference halls with many users
- **QoS Sensitivity:** Environments running VoIP or real-time streaming that require low latency
## Load Balancing
Load balancing distributes clients among neighboring APs to prevent any single node from becoming overloaded. Based on thresholds for client count or air utilization, the controller redirects new associations away from saturated APs to less busy ones.
### Implementation
- **Threshold-Based:** Define a maximum number of simultaneous associations per AP
- **Utilization-Based:** Measure channel utilization to balance not just client count but actual traffic load
- **Sticky Clients:** Temporarily disable balancing for critical devices (e.g., security cameras)
## PMKSA Caching & Reassociation
Enabling PMKSA caching lets clients *reuse their previously derived PMKs* when moving between APs, which *removes the need for a full EAP-TLS handshake* on each roam; this means no additional identity or certificate exchanges are sent over the air after the first connection, preventing an attacker from capturing those credentials again, although the WPA 4-way handshake (or FT handshake) still occurs and must be protected with a strong key.
### Configuration in `hostapd`
```bash
pmksa=1                      # 0 = disabled, 1 = enabled
max_num_sta=200              # Maximum number of cached PMKSA entries
reassociation_deadline=1000  # Time in ms for a client to complete reassociation
```
## Protected Management Frames (MFP)
Requiring 802.11w enforces cryptographic protection on management frames such as deauthentication and disassociation, which blocks spoofing or injection attacks and greatly improves resilience against disconnect-based DoS and MITM attacks; clients without 802.11w support will be unable to connect until they are upgraded or replaced.
### Configuration in `hostapd`
```bash
ieee80211w=2    # 1 = optional, 2 = required
pmk_r1_push=1   # Push FT R1 key to AP for faster handoff under 802.11r
```
## VLAN Segmentation
Dynamic [VLAN](../../networking/design-structure/VLANs.md) assignment isolates each client's traffic at [layer 2](../../networking/OSI/2-datalink/MAC-layer.md) by mapping them into separate VLANs, *containing any compromise or broadcast-based attack within that VLAN and preventing lateral movement*, although misconfiguration of VLANs or bridges can inadvertently expose sensitive networks if not carefully managed.
### Configuration in `hostapd`
```bash
dynamic_vlan=1
vlan_file=/etc/hostapd.vlan
vlan_tagged_interface=wlan0
vlan_bridge=br_mgt
```
## Protected Access Credential (PAC) in Wi-Fi and Management Networks
In EAP-FAST (RFC 4851), a Protected Access Credential (PAC) is an opaque credential that accelerates the establishment of TLS tunnels after the initial provisioning. By using a PAC, the full TLS handshake does not need to be repeated for each subsequent authentication.
### PAC Provisioning
1. During the first EAP-FAST authentication, the EAP server delivers a PAC to the supplicant, along with metadata such as the server ID and PAC validity period
2. Delivery occurs within an EAP-FAST-Response frame, encapsulated in an EAPoL (management) frame
3. The PAC contains derived keys and tunnel parameters, encrypted and authenticated with a message authentication code (MAC)
### PAC Format and Storage
- **Binary structure:** `[version | length | encrypted_data | MAC]`, where encrypted_data contains the session keys and parameters for the PRF (pseudo-random function)
- **Server storage:** encrypted file (e.g., /etc/hostapd/fast_pac_list)
- **Client storage:** operating-system keystore or protected on-disk file.
- **Default expiration:** PACs expire by default after 604800 seconds (7 days) in hostapd; this is configurable via the pac_key_lifetime (hard limit) and pac_key_refresh_time (soft refresh threshold) settings
### Subsequent Authentications with PAC
- The supplicant includes the PAC-opaque field in its EAP-FAST-Request, thereby skipping the full TLS handshake
- Session keys are derived via an optimized PRF operation using the PAC, which reduces latency and CPU usage
- Only EAP-FAST-Protect messages (for PAC verification and tunnel context establishment) are exchanged; no certificates or `ClientHello` messages appear
### Configuring PAC in `hostapd`
```bash
# hostapd.conf
eap_server=1
eap_user_file=/etc/hostapd/fast_user_file
fast_pac_file=/etc/hostapd/fast_pac_list
fast_provisioning=1
fast_prov_batch=1
logger_syslog_level=3
# Optional PAC lifetime settings:
#pac_key_lifetime=604800        # hard limit (7 days)
#pac_key_refresh_time=86400     # soft threshold (1 day)
```
The `fast_user_file` must contain lines formatted as `<Identity> <Password> <PAC-Alias>`. For example:
```bash
# identity   password     pac-alias
user1        secretpass   user1-pac
```
If `fast_pac_list` does not exist, it is created automatically upon the first provisioning. Alternatively, it can be preloaded using the `fast_prov_list` option or via the `hostapd_cli` tool.
### Capturing Identity and Handshake after a Deauthentication using PAC
#### **Injecting deauth:** 
```bash
aireplay-ng --deauth 1 -a <BSSID_AP> -c <MAC_client> wlan0`
```
#### **Collecting Identity:**
```bash
eap.code == 1 || eap.code == 2
```
EAP-Request/Identity and EAP-Response/Identity frames are captured in cleartext.
#### **Full TLS handshake:**
Occurs only if the PAC is absent or has expired. In this scenario, a full TLS handshake is performed: ClientHello, ServerHello, and the server Certificate messages are observed; no client certificate is used.
#### **Fast reauth with valid PAC:**
In this case, only the PAC verification and key derivation messages are exchanged; no certificates or ClientHello messages appear.

> [!Resources]
> - [Wifi Challenge Academy](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442649-wi-fi-attacks-mgt)
