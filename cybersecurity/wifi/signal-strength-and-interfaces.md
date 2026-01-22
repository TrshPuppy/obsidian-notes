# WiFi Interfaces
Wireless interfaces are the medium through with devices transmit and receive data from and on a wireless network. There are wifi interfaces which are capable of handling the 2.4GHz frequency or the 5GHz frequency or both ("dualband").
## Signal Strength 
Wifi signal strength is measured in decibel-milliwatts (dBm) which is used to express the power ratio in decibels to milliwatt. The relationship b/w dBm and milliwatts is defined by the following formula:
```
dBm = 10 * log10(Power in mW)
OR
Power in mW = 10^(dBm / 10)
```
This means that *a small change in dBm can represent a large change in signal power*. For example, an increase of 3 dBm represents a *doubling of signal power*. 

|dBm Range|Signal Quality|Expected Performance|Common Issues|
|---|---|---|---|
|-30 dBm to -50 dBm|Excellent|Maximum data rates, highly reliable connection.|Rare, potentially caused by interference.|
|-50 dBm to -60 dBm|Good|High data rates, reliable connection.|Minor speed reductions in crowded networks.|
|-60 dBm to -70 dBm|Acceptable|Moderate data rates, generally reliable connection.|Noticeable speed reductions, some packet loss.|
|-70 dBm to -80 dBm|Weak|Low data rates, unreliable connection.|Frequent disconnects, high latency.|
|-80 dBm to -90 dBm|Very Weak/Unusable|Extremely low data rates, very unreliable connection.|Connection highly intermittent, often unusable.|
### Factors Effecting Strength
- **Distance**: Signal strength decreases as distance from the access point increases
- **Obstacles**: Obstacles b/w clients and the access point decrease the signal's strength, especially depending on the kind of material (different materials have different *attenuation characteristics*)
- **Interference**: Other wireless devices (microwaves, bluetooth, other wifi networks) can interfere with a signal and decrease its strength
- **Antenna Gain & Type**: Antennas with a *higher gain* can concentrate a signal *in a specific direction* which increases its strength in that direction. Different antenna types have different *radiation patterns* (for example: omnidirectional, directional, etc.)
- **Frequency Band**: The difference in frequency b/w the 2.4 and 5GHz bands affects their signal strength and reach
	- *2.4GHz* (lower frequency): weaker signal but longer range
	- *5GHz* (higher frequency): stronger signal but shorter range
- **Transmit Power**: The transmit power of both the client and AP affect the signal's strength and their are *regulatory limits* in different regions which restrict the maximum transmit power allowed
- **Channel Selection**: Selecting a less congested Wifi channel can improve signal quality and strength by *reducing interference*

### Interface Strength
Some interfaces/"cards" are limited in their signal strength, meaning they may have a hard time operating at larger and longer ranges. To check for a card's strength we can use the following linux command:
```bash
trshpuppy@htb[/htb]# iwconfig

wlan0     IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=20 dBm   
          Retry short  long limit:2   RTS thr:off   Fragment thr:off
          Power Management:off
```
In the output we can see that our wireless interface has a `Tx-Power` set to `20 dBm`. This is determined by the *country specified in the [operating-system](../../computers/concepts/operating-system.md)* since transmit power is regulated by region.

We can use the `iw reg` command in linux to check what our region is set to:
```bash
trshpuppy@htb[/htb]# iw reg get

global
country 00: DFS-UNSET
        (2402 - 2472 @ 40), (6, 20), (N/A)
        (2457 - 2482 @ 20), (6, 20), (N/A), AUTO-BW, PASSIVE-SCAN
        (2474 - 2494 @ 20), (6, 20), (N/A), NO-OFDM, PASSIVE-SCAN
        (5170 - 5250 @ 80), (6, 20), (N/A), AUTO-BW, PASSIVE-SCAN
        (5250 - 5330 @ 80), (6, 20), (0 ms), DFS, AUTO-BW, PASSIVE-SCAN
        (5490 - 5730 @ 160), (6, 20), (0 ms), DFS, PASSIVE-SCAN
        (5735 - 5835 @ 80), (6, 20), (N/A), PASSIVE-SCAN
        (57240 - 63720 @ 2160), (N/A, 0), (N/A)
```
From the output, we can see that our region is set as `DFS-UNSET` which limits us to `20dBm`.
#### Changing Region for our Interface
To change our region (and get a better power setting for our interface) we can use the same command with the `set` keyword and our region's two letter code. For example, if we want to change our region to the US, we would do:
```bash
trshpuppy@htb[/htb]# sudo iw reg set US
```
We can use the `get` keyword to check the setting again and make sure it changed:
```bash
trshpuppy@htb[/htb]# iw reg get

global
country US: DFS-FCC
        (902 - 904 @ 2), (N/A, 30), (N/A)
        (904 - 920 @ 16), (N/A, 30), (N/A)
        (920 - 928 @ 8), (N/A, 30), (N/A)
        (2400 - 2472 @ 40), (N/A, 30), (N/A)
        (5150 - 5250 @ 80), (N/A, 23), (N/A), AUTO-BW
        (5250 - 5350 @ 80), (N/A, 24), (0 ms), DFS, AUTO-BW
        (5470 - 5730 @ 160), (N/A, 24), (0 ms), DFS
        (5730 - 5850 @ 80), (N/A, 30), (N/A), AUTO-BW
        (5850 - 5895 @ 40), (N/A, 27), (N/A), NO-OUTDOOR, AUTO-BW, PASSIVE-SCAN
        (5925 - 7125 @ 320), (N/A, 12), (N/A), NO-OUTDOOR, PASSIVE-SCAN
        (57240 - 71000 @ 2160), (N/A, 40), (N/A)
```
Now our region is set to the US which means we can use `30dBm` of power. Next, we need to edit our interface so it can use the full `30dBm`
#### Fixing the Interface
Our interface should automatically adopt the max power setting for our region, but if it hasn't we can force it to with the following commands:
```bash
trshpuppy@htb[/htb]# sudo ifconfig wlan0 down

trshpuppy@htb[/htb]# sudo iwconfig wlan0 txpower 30

trshpuppy@htb[/htb]# sudo ifconfig wlan0 up
```
Now, when we check the interface, it should show the following:
```bash
trshpuppy@htb[/htb]# iwconfig

wlan0     IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=30 dBm   
          Retry short  long limit:2   RTS thr:off   Fragment thr:off
          Power Management:off
```
Sometimes the above changes may not work. This can be due to a few reasons. First, it may be that the chip's manufacturer did not equip the device with the necessary heat sync to handle increased power output. Second, the [kernel](../../computers/concepts/kernel.md) itself may be patched *to prevent modification*. And lastly, the chip itself might not support increased power.





> [!Resources]
> - [CLRN: dBm and Wifi](https://www.clrn.org/what-is-a-good-dbm-for-wifi/)