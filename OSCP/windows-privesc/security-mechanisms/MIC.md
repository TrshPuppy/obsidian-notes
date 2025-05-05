
# Mandatory Integrity Control
Mandatory Integrity Control (MIC) restricts access to objects *based on pre-defined integrity levels*. Integrity levels are used in [Windows](../../../computers/windows/README.md) systems to *define how much trust Windows assigns to objects and applications*. This prevents lower integrity level processes from modifying higher-integrity ones.
## Inheritance
New processes and objects *inherit* their integrity level from the user who creates them. If an executable *has low integrity*, whatever process it spawns will inherit its same integrity level. Again, users with low integrity cannot modify objects with higher integrity, *even with the right permissions*. 
## Integrity Levels
Since Windows Vista, processes have five integrity levels they can run on:
### System Integrity
Reserved for [kernel](../../../computers/concepts/kernel.md)-mode processes with `SYSTEM` privileges.
### High Integrity
Processes with `Administrative` privileges. Just because the user executing the process or app is an admin *does not mean it automatically gains high integrity*. This is because the [UAC](UAC.md) ensures all processes/ apps run at a default *medium integrity* level
### Medium Integrity
Processes running with standard *user privileges*.
### Low Integrity
Restricted processes. Most often used for *security sandboxing* (like for web browsers).
### Untrusted
This is the lowest integrity level and is assigned to *highly restricted* processes which have been deemed to potentially pose a security risk to the system.
## Process Explorer
To check a process' integrity level, we can use the [Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer). The following image shows two [powershell](../../../computers/windows/powershell.md) processes listed in Process Explorer and their corresponding integrity levels:
![](../../oscp-pics/MIC-1.png)
`Medium` likely indicates the process was started by a standard user. `High` likely indicates it was started by an `Administive` user. 

> [!Resources]
> - [Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
> - [Microsoft: MIC](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
> - [Microsoft: Integrity Levels](https://learn.microsoft.com/en-us/previous-versions/dotnet/articles/bb625957(v=msdn.10)?redirectedfrom=MSDN)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.