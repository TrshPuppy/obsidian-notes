# Online Bruteforce Attack
Even though [SAE](../../networking/wifi/WPA3.md#SAE) is resistant to brute force attacks, they can still be attempted. 
## Wacker
[`wacker`](https://github.com/blunderbuss-wctf/wacker) is a tool that performs online brute force attacks against [WPA3](../../networking/wifi/WPA3.md) networks using the `wpa_supplicant` tool:
```bash
./wacker.py --wordlist <DICTIONARY> --ssid <ESSID> --bssid <BSSID> --interface <INTERFACE> --freq <FRECUENCIA_CANAL>
```
- `--wordlist`: path to a wordlist file to be used as the dictionary for brute forcing
- `--ssid`: the SSID of the target network
- `--bssid`: the BSSID of the target AP
- `--interface`: the interface to use
- `--freq`: the channel frequency of the target network
### Frequency
To figure out the frequency of a given channel, you can refer to the table on [Wikipedia](https://en.wikipedia.org/wiki/List_of_WLAN_channels):
![](../CWP-pics/online-bruteforce-1.png)
Or, you can use the command line on linux to determine it:
```bash
sudo iwlist wlan0 frequency | grep 'Channel 12 :'
```
## Airgeddon
Alternatively, you can use `airgeddon` with the `wpa3_online_attack` plugin. You can find the plugin [here](https://github.com/OscarAkaElvis/airgeddon-plugins/tree/main/wpa3_online_attack).


> [!Resources]
> - [GitHub - blunderbuss-wctf/wacker](https://github.com/blunderbuss-wctf/wacker)
> - [List of WLAN channels - Wikipedia](https://en.wikipedia.org/wiki/List_of_WLAN_channels)
> - [airgeddon-plugins/wpa3_online_attack at main](https://github.com/OscarAkaElvis/airgeddon-plugins/tree/main/wpa3_online_attack)
> - [Wifi Challenge Academy](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442980-introduction)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.