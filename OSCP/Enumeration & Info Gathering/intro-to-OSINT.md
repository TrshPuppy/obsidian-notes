
# Passive Reconnaissance
Also known as [OSINT](../../cybersecurity/TTPs/recon/OSINT.md) (open source intelligence) gathering. The process of finding and collecting *publicly available information* on a target *without directly interacting* with the target. The ultimate goal of passive reconnaissance is to *discover information which clarifies or expands the target's attack surface.* We're interested in any information which will help us exploit the target, whether by [phishing](../../hidden/Sec+/24%%201%20Attacks,%20Threats%20&%20Vulnerabilities/1.1%20Social%20Engineering/phishing.md), malware delivery, password guessing, etc..
## Schools of Thought
... on what 'passive' actually means.
### Strict interpretation
We *NEVER* communicate directly w/ the target and instead rely on *third-party* information. In other words, we *never interact with the target's systems or servers*. 

Strict passive recon maintains secrecy so the target can't guess at or know our actions or intentions. However, it can also be *cumbersome* and slow-going.
### Loose interpretation
Gathering OSINT by interacting with the target *as a normal user would*. For example, if the target's website has a 'register user' function, then we use it as a normal user would to try and gain information about the target.

We would *not do any testing* of the target for vulnerabilities, etc.. The idea is to gather public information which is readily available to any internet user. This type of reconnaissance *leaves a trace* or our actions which the target may discover and use to try to interpret our intentions (or as a means to re-create/ track down steps we take later on).
