
# MITRE ATT&CK Matrix
MITRE ATT&CK is A Cybersecurity framework used to track adversaries and the TTPs (tactics, techniques, and procedures) they use. MITRE itself is a non-profit institution which developed the framework. 

ATT&CK is an acronym which stands for Adversarial Tactics Techniques & Common Knowledge. It's a collection of information organized into a *matrix of techniques and sub techniques*. It also tracks specific *adversarial groups*. 
## Groups
If you go to their website and click [CTI -> Groups](https://attack.mitre.org/groups/) you can see a list of groups including APTs (Advanced Persistent Threat) and other named associations.

Each group has a *unique ID* to help track them since they're often given multiple pseudonyms. If you click on a group, you can see a list of *the techniques they've been noted using*.
![](/cybersecurity/cybersecurity-pics/mitre-attack-1.png)
> [MITRE ATT&CK](https://attack.mitre.org/groups/G0006/)
## Techniques
The [front page] of MITRE ATT&CK has a table of techniques and sub-techniques. There are 14 major techniques which include:
- Reconnaissance
- Resource Development
- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Command and Control
- Exfiltration
- Impact
Each of these can be expanded to see various sub-techniques. For example, if you click on [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583/) (which is a sub-technique of Resource Development), you're taken to a page describing it as a sub-technique.

Each sub-technique may be broken down further into their own sub-techniques. For example, the Acquire Infrastructure sub-technique includes its own sub-techniques like [*Acquire Infrastructure: Domains*](https://attack.mitre.org/techniques/T1583/001/). The page also includes *mitigations and detection* as well as reference links.

Just like with the groups section of the matrix, techniques and sub-techniques have their own IDs.

> [!Resources]
> - [Cyber Gray Matter: MITRE ATT&CK Framework for Beginners](https://www.youtube.com/watch?v=GYyLnff2XRo)
> - [MITRE ATT&CK](https://attack.mitre.org/)


