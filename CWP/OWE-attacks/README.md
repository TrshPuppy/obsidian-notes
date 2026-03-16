---
aliases:
  - OWE attacks
---
# OWE Attacks
OWE (Opportunistic Wireless Encryption) was introduced alongside [SAE](WPA3.md)/WPA3 and offers an alternative for networks that were previously completely open (OPN networks). In OWE, user traffic *is [encrypted](../../OSCP/password-attacks/README.md)* without requiring a shared password.

However, OWE networks are still vulnerable to some attacks. For instance, attackers can still perform attacks to bypass the [captive portal](../../CWP/OPN-attacks/captive-portal-bypass.md), or create [evil twin](../../CWP/PSK-attacks/evil-twin.md) or [fake AP](../../CWP/OPN-attacks/fake-AP.md) networks.

Essentially, the same [attacks which threaten OPN networks](../OPN-attacks/README.md) can be used against OWE networks, just with the caveat that *user traffic is encrypted and can't be viewed*.
## Attacks
### Evil Twin
Just like [fake AP](../OPN-attacks/fake-AP.md) or [evil twin](../PSK-attacks/evil-twin.md) attack in OPN and PSK networks, an evil twin attack in OWE networks works by creating a fake or rogue AP that looks like the target network.

The goal of this attack is to trick users into connecting to the fake network so you can capture their traffic and analyze it. This attack doesn't attack the target network directly, but its users.
### Social Engineering Attacks
An attacker can set up a fake [captive portal](../OPN-attacks/captive-portal-bypass.md) which mimics the target network's to try and trick users into connecting to it, entering their password, or clicking on phishing links. 

After tricking the user into entering their credentials (or clicking a link), attackers can then redirect users to more malicious sites and continue to attack them.
### MitM Attacks
Using [MAC Spoofing](../OPN-attacks/captive-portal-bypass.md#MAC%20Spoofing) or [DNS spoofing](../OPN-attacks/captive-portal-bypass.md#DNS%20Tunnel) attackers can intercept and alter communication sent between the target AP and its clients. This allows the attacker to potentially capture sensitive data, modify communications, or even inject malware into a user's connection.
### Dragondrain on OWE
Because OWE networks use [SAE](../../networking/wifi/WPA3.md), they are vulnerable to denial of service attacks like [dragondrain](../SAE-attacks/dragondrain.md).


> [!Resources]
> - [Wifi Challenge Academy](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442980-introduction)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.