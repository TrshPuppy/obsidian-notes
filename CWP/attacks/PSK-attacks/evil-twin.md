---
aliases:
  - evil twin
  - evil twin attack
---
# Evil Twin Attacks
In an evil twin attack, you create a [fake AP](../OPN-attacks/fake-AP.md) with the goal of *tricking client devices into authenticating to it*. The end result is a *username and hashed password* which we can crack using [john](../../../cybersecurity/TTPs/cracking/tools/john.md) or [asleap](https://www.kali.org/tools/asleap/).

In order for the attack to work, clients have to be using devices which are configured *to accept invalid server certificates* or they have to *manually accept* the evil twin's invalid certificate

> [!Resources]
> - [asleap | Kali Linux Tools](https://www.kali.org/tools/asleap/)
> - 