# Wired Equivalent Privacy
WEP is a [WiFi](802.11.md) protocol which is outdated and has *very weak* encryption. It was the *first* attempt to encrypt wifi back in 1999. The idea was to create a wireless [LAN](../design-structure/LAN.md) with [encryption](../../OSCP/password-attacks/README.md) equivalent to wired LAN. It was eventually replaced with [WPA/WPA2](WPA-WPA2.md) in 2003, then 2004 respectively.
## Key Concepts
- **Initialization Vector** (IV): A random value used alongside a secret key to encrypt packets. The IV used in WEP is *24 bits long* which means it is frequently re-used
- **RC4 Stream Cipher**: WEP uses RC4 for encryption, however there are flaws in the RC4 implementation in WEP which make it easier to predict the key stream which compromises security
- **Integrity Check Value** (ICV): WEP uses an ICV to verify packet *integrity* via a non-cryptographic [checksum](../../cybersecurity/opsec/checksums.md)
- **Shared Key Authentication** (SKA): WEP uses SKA which entails devices sharing a static key in order to authenticate. Attackers can deduce the key because the authentication is insecure and exposes parts of the encryption process


> [!Resources]
> - [Certified WiFiChallenge Professional (CWP) - (Course + Exam) - WiFiChallenge Academy](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57443050-wi-fi-attacks-wep-wired-equivalent-privacy)

> [!Related]
> - My notes on [hacking WEP](../../CWP/WEP-attacks/)

