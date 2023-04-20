
# Windows Enumeration:
The first thing you should do when you gain access to a Windows machine is enumeration.

## Users
```PowerShell
Get-LocalUser
Name           Enabled Description
----           ------- -----------
Administrator  True    Built-in account for administering the computer/domain
DefaultAccount False   A user account managed by the system.
duck           True
duck2          True
Guest          False   Built-in account for guest access to the computer/domain
```

Each user has an SID:
```PowerShell
Get-Localuser | select-object -property side, name
SID                                            Name
---                                            ----
S-1-5-21-1394777289-3961777894-1791813945-500  Administrator
S-1-5-21-1394777289-3961777894-1791813945-503  DefaultAccount
S-1-5-21-1394777289-3961777894-1791813945-1008 duck
S-1-5-21-1394777289-3961777894-1791813945-1009 duck2
S-1-5-21-1394777289-3961777894-1791813945-501  Guest
```

A user object, and all of its properties looks like this:
```PowerShell
AccountExpires         :
Description            : Built-in account for guest access to the computer/domain
Enabled                : False
FullName               :
PasswordChangeableDate :
PasswordExpires        :
UserMayChangePassword  : False
PasswordRequired       : False
PasswordLastSet        :
LastLogon              :
Name                   : Guest
SID                    : S-1-5-21-1394777289-3961777894-1791813945-501
PrincipalSource        : Local
ObjectClass            : User
```

### Example: sorting my PasswordRequired property:
```PowerShell
get-localuser | where-object -property passwordRequired -like false

Name           Enabled Description
----           ------- -----------
DefaultAccount False   A user account managed by the system.
duck           True
duck2          True
Guest          False   Built-in account for guest access to the computer/domain
```

## Groups:
```PowerShell
Get-localgroup
Name                                Description
----                                -----------
Access Control Assistance Operators Members of this group can remotely query authorization attributes and permission...
Administrators                      Administrators have complete and unrestricted access to the computer/domain
Backup Operators                    Backup Operators can override security restrictions for the sole purpose of back...
Certificate Service DCOM Access     Members of this group are allowed to connect to Certification Authorities in the...
Cryptographic Operators             Members are authorized to perform cryptographic operations.
Distributed COM Users               Members are allowed to launch, activate and use Distributed COM objects on this ...
```

## Network:
### IP Address:
```Powershell
Get-NetIPAddress
```

### Ports:
```
Get-NetTCPConnection
```

## Installations/ Patches
### Hot-Fixes:
```
Get-HotFix
```

### CIM Instance:
Use `Get-CimInstance` to get the [Common Interface Model (CIM)](https://www.techtarget.com/searchstorage/definition/Common-Information-Model) instance of a class from the CIM server:
```PowerShell
Get-CimInstance -Class win32_quickfixengineering
Source        Description      HotFixID      InstalledBy          InstalledOn
------        -----------      --------      -----------          -----------
              Update           KB3176936                          10/18/2016 12:00:00 AM
              Update           KB3186568     NT AUTHORITY\SYSTEM  6/15/2017 12:00:00 AM
              Update           KB3192137     NT AUTHORITY\SYSTEM  9/12/2016 12:00:00 AM
              Update           KB3199209     NT AUTHORITY\SYSTEM  10/18/2016 12:00:00 AM
              Update           KB3199986     EC2AMAZ-5M13VM2\A... 11/15/2016 12:00:00 AM
              Update           KB4013418     EC2AMAZ-5M13VM2\A... 3/16/2017 12:00:00 AM
              ...
```

## Backup files:
Backup files are normally saves with the `.bak` extension. To find a specific backup file:
```powershell
Get-ChildItem -Recurse -ErrorAction SilentlyContinue -Include *.bak* -File

```

## Running Processes:
```
Get-Process
```

## Drive Ownership:
```
Get-Acl C:/
```