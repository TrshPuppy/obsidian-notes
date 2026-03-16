---
aliases:
  - WEP attacks
---
# WEP Attacks
[WEP](../../networking/wifi/WEP.md) (Wireless Equivalent Privacy) is the oldest [wifi](../../networking/wifi/802.11.md) authentication standard and is VERY VULNERABLE to attack. Most WEP attacks hinge on the attacker's ability to capture *IV (Initialization Vector) packets*.

If an attacker can capture the IV, they can easily compromise the network because the IV is used to encrypt traffic via a secret key.