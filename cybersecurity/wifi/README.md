---
aliases:
  - wifi pentesting
---
# Wifi Pentesting Basics
## Authentication
There are four main types of authentication in wifi, each progressively more secure:
- WEP (Wireless Equivalent Privacy): outdated and insecure- does include some basic encryption but also has a lot of vulnerabilities
- WPA (Wifi Protected Access): better encryption than WEP using *Temporal Key Integrity Protocol* (TKIP), but is still insecure compared to newer standards
- WPA2: uses Advanced Encryption Standard ([AES](../../computers/concepts/cryptography/AES.md)) - used in most networks and provides strong protection
- WPA3: the latest standard - adds individualized encryption, and more robust password-based authentication
## 802.11 Frames and Types
![My notes on IEEE 802.11](../../networking/wifi/802.11.md)