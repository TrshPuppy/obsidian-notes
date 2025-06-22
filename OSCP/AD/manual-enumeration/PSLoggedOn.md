
# `PSLoggedOn.exe`
> [!Note]
> For these notes, the following *scenario* applies: we're enumerating the `corp.com` domain. We've obtained user credentials to a domain user through a successful phishing attack. The user we have access to is `stephanie` who has remote desktop permissions on a Windows 11 machine `CLIENT75` which is a part of the domain. This user is not a local administrator on the machine. The scope is restricted to the `corp.com` domain.
> 
> We have remoted into `CLIENT75` using [xfreerdp](../../../CLI-tools/linux/remote/xfreerdp.md) via the [RDP](../../../networking/protocols/RDP.md) protocol:
> `kali@kali:~$ xfreerdp /u:stephanie /d:corp.com /v:192.168.50.75`

Since we've established that `Get-NetSession` (from [PowerView](../../../cybersecurity/TTPs/actions-on-objective/tools/PowerView.md)) may not work on more up to date operating systems, we can try a similar tool called [_PsLoggedOn_](https://learn.microsoft.com/en-us/sysinternals/downloads/psloggedon). PsLoggedOn is an application from the [_SysInternals Suite_](https://learn.microsoft.com/en-us/sysinternals/) of tools

According to the docs, `PSLoggedOn` works by *enumerating the registry keys* under `HKEY_USERS` to retrieve the [SID](../../windows-privesc/security-mechanisms/SID.md)s of logged in users. It then *converts the SIDs to usernames*. Just like [`Get-NetSession`](PowerView.md#`Get-NetSession`) in PowerView, `PSLoggedOn` also uses the `NetSessionEnum` API to identify which users *are logged on* to the computer via shares. 
## Drawbacks
Unfortunately, `PSLoggedOn` relies on the *Remote Registry* service which is *not enabled by default* (since Windows 8). However, some sysadmins may enable it for administrative tasks and backwards compatibility. It's also installed by default on some later versions of *Windows Server*:
- Server 2012 R2
- 2016 (1607)
- 2019 (1809)
- 2022 (21H2)
### Inactivity
Another drawback to remember is that after *ten minutes of inactivity* Remote Registry Service will stop to save resources. But you can keep it from stopping with something like a timed automatic trigger.
## Enumerating with `PSLoggedOn`
To enumerate the machines in our scenario (`CLIENT74`, `FILES04` and `WEBO4`), we can just provide them in the command:
### User is logged on
In the output, a logged on use is reported like this:
```powershell
PS C:\Tools\PSTools> .\PsLoggedon.exe \\client74

PsLoggedon v1.35 - See who's logged on
Copyright (C) 2000-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

Users logged on locally:
     <unknown time>             CORP\jeffadmin

Users logged on via resource shares:
     10/5/2022 1:33:32 AM       CORP\stephanie
```
Notice that `jeffadmin` is logged on locally to the machine, while `stephanie` is connected via a *resource share*.
### User is not logged on
```powershell
PS C:\Tools\PSTools> .\PsLoggedon.exe \\web04

PsLoggedon v1.35 - See who's logged on
Copyright (C) 2000-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

No one is logged on locally.
Unable to query resource logons
```


> [!Resources]
> - [_PsLoggedOn_](https://learn.microsoft.com/en-us/sysinternals/downloads/psloggedon)
> - [_SysInternals Suite_](https://learn.microsoft.com/en-us/sysinternals/)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.