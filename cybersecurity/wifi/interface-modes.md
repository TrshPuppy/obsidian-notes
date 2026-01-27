# Wifi Interface Modes
In [wifi](../../networking/wifi/802.11.md) communications, there are multiple capabilities and roles that an interface can function under.
## Managed Mode
In managed mode our interface acts as a client or "station." Its role in this mode is to authenticate with access point (AP) devices. In this mode, our interface will search for APs to which it can establish a connection.

This is the default mode that our interface will be in. But, if we want to force this mode (for example, if we set it in a different mod3e and want to return to managed mode), then we can with the following set of commands:
```bash
trshpuppy@htb[/htb]# sudo ifconfig wlan0 down
trshpuppy@htb[/htb]# sudo iwconfig wlan0 mode managed
```
### Connecting to a Network
While in managed mode we can connect to a specific network using the command line with the following command:
```bash
trshpuppy@htb[/htb]# sudo iwconfig wlan0 essid HTB-Wifi
```
After connecting, we can check to make sure it worked with the `iwconfig` command:
```bash
trshpuppy@htb[/htb]# sudo iwconfig

wlan0     IEEE 802.11  ESSID:"HTB-Wifi"  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=30 dBm   
          Retry short  long limit:2   RTS thr:off   Fragment thr:off
          Power Management:off
```
## Ad-hoc Mode
Ad-hoc mode allows wireless interfaces to communicate directly with one another (peer-to-peer). It is commonly used in residential mesh networks to allow APs to communicated directly in *backhaul bands*.
### Setting Ad-hoc Mode
To set our interface to ad-hoc mode we can run the following commands:
```bash
trshpuppy@htb[/htb]# sudo iwconfig wlan0 mode ad-hoc
trshpuppy@htb[/htb]# sudo iwconfig wlan0 essid HTB-Mesh
trshpuppy@htb[/htb]# sudo iwconfig

wlan0     IEEE 802.11  ESSID:"HTB-Mesh"  
          Mode:Ad-Hoc  Frequency:2.412 GHz  Cell: Not-Associated   
          Tx-Power=30 dBm   
          Retry short  long limit:2   RTS thr:off   Fragment thr:off
          Power Management:off
```
## Master Mode
In master mode our interface would act as an AP and would be able to serve connections to other clients/ stations.
### Setting Master Mode
Unlike the previous modes, we can't just use `iwconfig` to set our interface in master mode because in master mode it is essentially acting as a whole-ass server. So, instead, we can use the `hostapd` utility.
#### Configuration File
To use `hostapd`, first we need a configuration file which will tell `hostapd` how to set up our wireless AP:
```bash
interface=wlan0
driver=nl80211
ssid=Hello-World
channel=2
hw_mode=g
```
This configuration tells `hostapd` to setup an open wireless network with the name `Hello-World`. We can bring up our new network using the following `hostapd` command:
```bash
trshpuppy@htb[/htb]# sudo hostapd open.conf

wlan0: interface state UNINITIALIZED->ENABLED
wlan0: AP-ENABLED 
wlan0: STA 2c:6d:c1:af:eb:91 IEEE 802.11: authenticated
wlan0: STA 2c:6d:c1:af:eb:91 IEEE 802.11: associated (aid 1)
wlan0: AP-STA-CONNECTED 2c:6d:c1:af:eb:91
wlan0: STA 2c:6d:c1:af:eb:91 RADIUS: starting accounting session D249D3336F052567
```
The above output also features what it would look like if another host connected to our network (line 7). The successful connection indicates our AP is working well.
## Mesh Mode
In mesh mode, the interface is configured to join a "self-configuring and routing" network. It's commonly used for business applications which need to cover a large physical space. In mesh mode, the interface becomes a *mesh point*.

In a mesh network, there are several devices broadcasting the wifi network. This helps improve the strength of the signal. Each device acts as an access point, so instead of having one access point, there are several.
### Commands
One way to check if our interface can handle mesh mode is to check for errors when running this command (which sets the mode type to mesh):
```bash
trshpuppy@htb[/htb]# sudo iw dev wlan0 set type mesh
```
## Monitor Mode
Monitor, or "promiscuous" mode, allows the interface to *capture all wireless traffic* w/i its range. Unlike other modes monitor mode *allows the interface to capture traffic even if the traffic is intended for a different recipient*.

Enabling monitor mode usually requires *admin privileges*:
```bash
trshpuppy@htb[/htb]# sudo ifconfig wlan0 down
trshpuppy@htb[/htb]# sudo iw wlan0 set monitor control
trshpuppy@htb[/htb]# sudo ifconfig wlan0 up
trshpuppy@htb[/htb]# iwconfig

wlan0     IEEE 802.11  Mode:Monitor  Frequency:2.457 GHz  Tx-Power=30 dBm   
          Retry short  long limit:2   RTS thr:off   Fragment thr:off
          Power Management:off
```
## Choosing a Mode for Pentesting
In most cases, monitor mode w/ the ability to inject packets is sufficient. But there are other specific attack types where the other modes become useful:
### Rogue AP/ Evil-Twin Attack
For these attacks, the interfave needs to support *master mode* with a management daemon like `hostapd`
### Backhaul & Mesh/ Mesh-Type Exploitation
For these attacks, the interface may need to support both *mesh mode* and *ad-hoc mode*. 



> [!References]
> - [How to Geek: Mesh Networks](https://www.howtogeek.com/290418/what-are-mesh-wi-fi-systems-and-how-do-they-work/)
> - [HTB Academy](https://academy.hackthebox.com/module/222/section/2402)

