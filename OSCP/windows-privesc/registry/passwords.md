
# Searching for Passwords in the Registry
Many programs *store configuration options* (including passwords) in the [registry](../../../computers/windows/registry.md). So, we should search for them in there.
## How
### Using `reg query`
We can use `reg query` to search specific trees in the registry for password. This usually returns a lot of results, so sometimes it's more efficient to search in *known locations*.
```powershell
PS C:\Users\admin> reg query HKLM /f password /t REG_SZ /s

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{0fafd998-c8e8-42a1-86d7-7c10c664a415}
    (Default)    REG_SZ    Picture Password Enrollment UX

...

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    DefaultPassword    REG_SZ    password123

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Internal.Shell.PlatformExtensions.PasswordEnrollment.PasswordEnrollmentManager
    DllPath    REG_SZ    C:\Windows\System32\PasswordEnrollmentManager.dll

...

End of search: 305 match(es) found.
```
The partial output above shows a password for `Winlogon` of `password123` (which I happen to know is the password for the `admin` user on this box). 
### Using winPEAS
For automated enumeration, you can use [winPEAS](../../../cybersecurity/TTPs/actions-on-objective/tools/winPEAS.md) with the `filesinfo` and `userinfo` modules. This checks for passwords *in common password locations* but sometimes takes a while to complete:
```powershell
PS C:\Users\admin> .\winPEASany.exe quiet filesinfo userinfo

...

  [+] Looking for AutoLogon credentials(T1012)
    Some AutoLogon credentials were found!!
    DefaultUserName               :  admin
    DefaultPassword               :  password123

...

  [+] Unnattend Files()
    C:\Windows\Panther\Unattend.xml
<Password>                    <Value>cGFzc3dvcmQxMjM=</Value>                    <PlainText>false</PlainText>                </Password>

...
```
In this partial output, we can see the AutoLogon password for the `admin` user as well as a password in an unattended file related to something called "Panther".