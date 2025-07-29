
# Passwords in Configuration Files
Sometimes admins will leave config files on the system and those files may have creds in them. For example, `Unattended.xml` is a common file which is used for automated setup of Windows systems. 
## Enumeration
To find configuration files with creds in them, you can use both automated and manual tactics.
### Manual
You can use the `dir` command and `findstr` command to recursively search for files in your current directory.
#### Using `dir` to search by filename
The following command will search recursively in the current directory for files with names either containing "pass" or ending in ".config" (this is for *Command Prompt*):
```cmd
C:\Users\admin>dir /s *pass* == *.config
 Volume in drive C has no label.
 Volume Serial Number is 30EF-5F16

 Directory of C:\Users\admin\AppData\Local\Microsoft\Edge\User Data\Autofill\4.0.1.25

07/17/2025  03:12 AM               146 autofill_bypass_cache_forms.json
               1 File(s)            146 bytes

 Directory of C:\Users\admin\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.1.0.0

02/26/2025  11:29 PM           241,951 passwords.txt
               1 File(s)        241,951 bytes

     Total Files Listed:
               2 File(s)        242,097 bytes
               0 Dir(s)  35,901,968,384 bytes free
```
#### Using `findstr` to search by name and extension
The following `findstr` command will recursively search the current directory for files containing the word "password" and which also have an extension of either .xml .ini or .txt (the output could be a lot) (also for Command Prompt):
```cmd
C:\Users\admin>findstr /si password *.xml *.ini *.txt
AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.1.0.0\passwords.txt:password

...

AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalState\DiagOutputDir\SkypeApp0.txt:2025-07-24 11:07:57.396-07:00 [6176:011] [Info] [RNKeyChainModule] Delete Password
AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalState\DiagOutputDir\SkypeApp0.txt:2025-07-24 11:07:57.427-07:00 [6176:011] [Info] [RNKeyChainModule] deletePassword - Deleted credentials
AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\ConstraintIndex\Apps_{4d183df9-cfc9-42d1-b33b-65428981a55f}\0.0.filtertrie.intermediate.txt:control userpasswords2~
AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\ConstraintIndex\Apps_{971e5ffc-5ebf-4a9a-beb3-d3784479626e}\0.0.filtertrie.intermediate.txt:control userpasswords2~
AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\ConstraintIndex\Apps_{c40c9198-5a11-44b4-aab6-3736daaa199e}\0.0.filtertrie.intermediate.txt:control userpasswords2~

...
``` 
### Using winPEAS
You can also use [winPEAS](../../../cybersecurity/TTPs/actions-on-objective/tools/winPEAS.md) to do this by running it with the `searchfast` and `filesinfo` modules:
```powershell
PS C:\Users\admin> .\winPEASany.exe quiet filesinfo searchfast
...

  [+] Unnattend Files()
    C:\Windows\Panther\Unattend.xml
<Password>                    <Value>cGFzc3dvcmQxMjM=</Value>                    <PlainText>false</PlainText>                </Password>

...

  [+] Looking for possible password files in users homes(T1083&T1081)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files
    C:\Users\admin\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.1.0.0\passwords.txt

...

    C:\PrivEsc(7/28/2025 6:23:39 PM)
    C:\PrivEsc\tiddies.txt(7/28/2025 6:23:39 PM)
```
In the output we can see that a file called `Unattend.xml` was found. Let's check it out:
```powershell
    C:\PrivEsc\tiddies.txt(7/28/2025 6:23:39 PM)
PS C:\Users\admin> type C:\Windows\Panther\Unattend.xml
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">

...
                <CommandLine>%AppsRoot%:\BootCamp\Drivers\ATI\ATIGraphics\Bin64\ATISetup.exe -Install</CommandLine>
                <Order>1</Order>
                <RequiresUserInput>false</RequiresUserInput>
              </SynchronousCommand>
              <SynchronousCommand wcm:action="add">
                  <Description>BootCamp setup</Description>
                  <CommandLine>%AppsRoot%:\BootCamp\setup.exe</CommandLine>
                  <Order>2</Order>
                  <RequiresUserInput>false</RequiresUserInput>
              </SynchronousCommand>
            </FirstLogonCommands>
            <AutoLogon>
                <Password>
                    <Value>cGFzc3dvcmQxMjM=</Value>
                    <PlainText>false</PlainText>
                </Password>
                <Enabled>true</Enabled>
                <Username>Admin</Username>
            </AutoLogon>
        </component>
    </settings>
</unattend>
```
Looks like the password is an AutoLogon password for the `Admin` user. The password is *base64 encoded*. Decoding it with the Linux `base64` command gives us the following:
```bash
┌─[25-07-28 22:03:41]:(root@10.0.2.15)-[~/tibs]
└─# echo "cGFzc3dvcmQxMjM=" | base64 -d
password123
```