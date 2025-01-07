
# Application Hardening
The process of securing an app by *limiting the attack surface*. Focused on protecting against well-known attack points, but also less-known ones. Some hardening techniques are *guided by compliance mandates* such as HIPAA and PCI DSS.
## Ports and Services
*Limiting what ports are accessible* on a device (besides the ones which are absolutely necessary). This includes getting rid or or disallowing ports which are opened by *unknown or unused services.* Every port is a *possible entry point,* so access to them should be controlled, usually with [firewalls](../firewalls.md).

Can use [nmap](../../../CLI-tools/linux/remote/nmap.md) to scan a device or network to see what ports are currently opened.
### Firewalls
Firewalls allow you to control access to specific ports and which [IP-addresses](../../../PNPT/PEH/networking/IP-addresses.md) can access them. Even better, a *Next Generation Firewall* will let you also limit the *applications* which are allowed to run on the current network IP address. 
## Windows Registry
![registry](../../../computers/windows/registry.md)
# Operating System Hardening
Methods and techniques for hardening/ securing an [operating-system](../../../computers/concepts/operating-system.md), some of which can be applied globally and some of which that are OS-dependent (differ b/w Windows, Linux, etc.).
## Disk Encryption
### FDE
**Full Disk Encryption**: Method for preventing access to application data files using [symmetric encryption](../../../computers/concepts/cryptography/symmetric-encryption.md). Usually via a service like BitLocker on Windows which encrypts everything on the drive. 
### SED
**Self-encrypting Drive**: This is FDE which is *built into the hardware of the drive itself.* This method *doesn't require OS-level software at all* and is not OS-dependent. Anything which is written to the drive *gets encrypted* b/c it's built into the device itself.
#### Opal Storage Specification
A standard for using/ applying encryption using SED.
## Global
### Updates
Making sure the operating system is updated with the most recent service packs, security patches, *device drivers*, *applications*, etc.. Auto updating *is not always the best idea* b/c some updates can *impact the system*. To avoid this (in an organization), the IT department will usually be responsible for *testing updates* before they're applied to all the devices.
#### Emergency "Out-of-Band" Updates
Usually pushed in the case of emergencies such as *new [zero-day](../../TTPs/exploitation/zero-day.md)s* being released.
### User Accounts
Ensure all user accounts have a password, use secure passwords and have appropriate limitations set on them depending on the user type.
### Network Access
Limit network access to other devices on the network, primarily *input from other devices*. 
### Monitoring
With anti-virus software, IDS, IPS, etc..
### Patch Management
SUPER IMPORTANT. Usually deployed by the OS vendor on a monthly basis and incrementally.
## Sandboxing
Sandboxing allows you to section off applications so they can't access unrelated resources. Sandboxing is commonly used during *application development*. With sandboxing, applications can't access data or resources beyond what you've *granted them access to*.

There are a lot of types of software/ deployments which use sandboxing including:
- virtual machines
- [containers](../../../computers/virtualization/containers.md)
- mobile devices
- browser iframes (inline frames): separated from each other
- Windows User Account Control (UAC)

> [!Resources]
> - [Professor Messer](https://www.youtube.com/watch?v=KxiPfczekFA&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=106)