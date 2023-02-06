
# BlueKeep Vulnerability
#### #CVE-2019-0708 
Vulnerability in Windows OSs using [[RDP]]

## Description:
This vulnerability exists in the #RDP used by the listed vulnerable OSs.
- An attacker can exploit this to perform #RCE on the target system. 
- After an attacker sends specially crafted packets they're able to:
	- add user accounts w/ full user rights including viewing, changing, deleting data, installing programs.
- #BlueKeep is "wormable" because malware exploiting this vulnerability can propagate to other devices and spread rapidly.

## Required Contexts:
1. Vulnerable Windows OSs:
	- Windows 2000
	- Vista
	- XP fhdjkhdjfhdkjah
	- 7
	- 2003, 2003 R2
	- 2008, 2008 R2
2. Exploit ==must occur before authentication== to work.

## Mitigation:
- Upgrade #EOL (end of life) devices
- enable #NLA Network Level Authentication with #CredSSP 
- block #TCP #port-3389 at the firewall

>[!links]
>https://www.cisa.gov/uscert/ncas/alerts/AA19-168A
>
>https://www.rapid7.com/blog/post/2019/11/07/the-anatomy-of-rdp-exploits-lessons-learned-from-bluekeep-and-dejablue/



