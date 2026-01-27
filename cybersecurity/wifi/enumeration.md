# Enumerating Wifi Networks
To find all of the available [wifi](../../networking/wifi/802.11.md) networks, we can use the linux `iwlist` command and give it the name of our testing interface. The output can be lengthy, so to filter it for the info we need, we're going to pipe to grep:
```bash
trshpuppy@htb[/htb]# iwlist wlan0 scan |  grep 'Cell\|Quality\|ESSID\|IEEE'

          Cell 01 - Address: f0:28:c8:d9:9c:6e
                    Quality=61/70  Signal level=-49 dBm  
                    ESSID:"HTB-Wireless"
                    IE: IEEE 802.11i/WPA2 Version 1
          Cell 02 - Address: 3a:c4:6e:40:09:76
                    Quality=70/70  Signal level=-30 dBm  
                    ESSID:"CyberCorp"
                    IE: IEEE 802.11i/WPA2 Version 1
          Cell 03 - Address: 48:32:c7:a0:aa:6d
                    Quality=70/70  Signal level=-30 dBm  
                    ESSID:"HackTheBox"
                    IE: IEEE 802.11i/WPA2 Version 1
```
From the output, we can see there are three wifi networks available. Our filter shows us important details including the *signal quality ESSID and IEEE specification*.