---
aliases:
  - OWE attacks
---
# OWE Attacks
OWE (Opportunistic Wireless Encryption) was introduced alongside [SAE](WPA3.md)/WPA3 and offers an alternative for networks that were previously completely open (OPN networks). In OWE, user traffic *is [encrypted](../../OSCP/password-attacks/README.md)* without requiring a shared password.

However, OWE networks are still vulnerable to some attacks. For instance, attackers can still perform attacks to bypass the [captive portal](../../CWP/OPN-attacks/captive-portal-bypass.md), or create [evil twin](../../CWP/PSK-attacks/evil-twin.md) or [fake AP](../../CWP/OPN-attacks/fake-AP.md) networks.

Essentially, the same [attacks which threaten OPN networks](../OPN-attacks/README.md) can be used against OWE networks, just with the caveat that *user traffic is encrypted and can't be viewed*.

> [!Resources]
> - [Wifi Challenge Academy](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442980-introduction)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.