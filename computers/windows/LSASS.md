INIT
# Local Security Authority Subsystem Service
A process (`lsass.exe`) on [Windows](README.md) computers which *enforces security policies*. It verifies users who are logging into the computer/ server, handles *password changes*, and creates *access tokens*. It also writes to the Windows Security Log.

`lsass.exe` is located at `%WINDIR%\System32`. If you were to force terminate `lsass.exe`, you could cause the system to *lose access to any accounts*, including system based ones, which would cause the machine to restart. 

> [!Resources]
> - [Wikipedia: LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)