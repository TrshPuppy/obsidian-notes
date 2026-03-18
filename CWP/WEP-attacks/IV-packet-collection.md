# Accelerating IV Packet Collection
In [WEP](../../networking/wifi/WEP.md), the IV (initialization vector) is a random value used along with a shared key to encrypt traffic. One of the main goals in WEP hacking is to *capture as many repeating IVs as possible* because it makes decryption easier.
## Fake Authentication
To speed up IV collection, you can send fake auth requests using tools like `aireplay-ng` in the [Aircrack-ng](../../cybersecurity/wifi/Aircrack-ng.md) suite. The idea is to trick the AP into thinking you're a client who *wants to authenticate*:
```bash
aireplay-ng -1 0 -a <BSSID> -h <client mac> <INTERFACE>
```
## ARP Request Replay
You can also collect IV packets by setting up an *arpreplay* attack. To do this, you can use `aireplay-ng` again. The idea is to capture valid [ARP](../../networking/protocols/ARP.md) packets, then repeatedly *re-inject them into the network*. This creates fake traffic which should cause an increase in IV generation:
```bash
aireplay-ng -3 -b <BSSID> -h <client mac> <INTERFACE>
```
## Deauthentication Attack
If there are legitimate clients auth'd to the target network, then you can temporarily force them to disconnect. When they reconnect and reauthenticate, this *generates new traffic* including new ARP requests with IVs:
```bash
aireplay-ng -0 1 -a <BSSID> -c <client mac> <INTERFACE>
```

> [!Resources]
>  - [Wifi Challenge Academy](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442980-introduction)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.