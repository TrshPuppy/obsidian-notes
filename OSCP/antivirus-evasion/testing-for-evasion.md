
# Testing for AV Evasion
During a penetration test, if we need to check if our malware can evade [antivirus](README.md), there are a few tools we can use.
## Tools
Relying on third-party tools should be a *last resort*, especially if you don't know the specifics of your target's AV system implementation. 
### VirusTotal
First, *avoid [Virus-Total](../../cybersecurity/TTPs/recon/tools/reverse-engineering/Virus-Total.md)* because as soon as you upload your sample *it becomes public* and is shared with AV manufacturers, etc..
### AntiScan.me
An alternative is [AntiScan.me]() which is a service that will scan our sample against 30 AV engines. It *claims* to not submit or divulge submitted samples to third parties, but don't rely on that. You can get up to 4 scans/day or additional ones for a fee.
### Dedicated VM
If you *do know* the specifics about your target's AV system, then a dedicated VM is a better option. This VM should *emulate the target's environment* as closely as possible.
#### Disabling Sampling
Some OS's, especially [Windows](../../computers/windows/README.md) will automatically *submit samples* to third parties if they detect them within the VM environment. Make sure to configure the VM in its settings to not do this.
## Other Considerations
Before starting *make sure the antivirus software is actually working*. You can do this by generating a [metasploit](../../cybersecurity/TTPs/exploitation/tools/metasploit.md) payload/ [PE](../../computers/windows/PE.md) and then transferring it into the VM. If the AV system detects it, you should immediately be met with a warning or notification.

Additionally, it's difficult to develop malware which evades *every kind of AV system*. So, to cut down on time and effort, develop your malware *specific to your target/client's environment* and AV implementation.

> [!Resources]
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.