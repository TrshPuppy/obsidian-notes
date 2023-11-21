
# BlueKeep Vulnerability
#### CVE-2019-0708 
Vulnerability in Windows OSs using [RDP](/networking/protocols/RDP.md)
## Description:
This vulnerability exists in the RDP protocol used by the listed vulnerable OSs. An attacker can exploit this to perform remote code execution (RCE) on the target system. 
### Mechanism
After an attacker sends specially crafted packets they're able to add user accounts w/ full user rights including viewing, changing, deleting data, and installing programs. Exploits of this vuln *must occur before authentication* to work.

BlueKeep is *"wormable"* because malware exploiting this vulnerability can propagate to other devices and spread rapidly.
## Vulnerable Windows OSs
- Windows 2000
- Vista
- XP 
- 7
- 2003, 2003 R2
- 2008, 2008 R2
## Mitigation
- Upgrade EOL (end of life) devices
- enable NLA (Network Level Authentication) with *CredSSP* 
- block [TCP](/networking/protocols/TCP.md) `port 3389` *at the firewall*

> [!Resources]
> - [CISA](https://www.cisa.gov/uscert/ncas/alerts/AA19-168A)
> - [Rapid7](https://www.rapid7.com/blog/post/2019/11/07/the-anatomy-of-rdp-exploits-lessons-learned-from-bluekeep-and-dejablue/)
