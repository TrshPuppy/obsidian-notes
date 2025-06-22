# Enumerating with PowerView
> [!Note]
> For these notes, the following *scenario* applies: we're enumerating the `corp.com` domain. We've obtained user credentials to a domain user through a successful phishing attack. The user we have access to is `stephanie` who has remote desktop permissions on a Windows 11 machine `CLIENT75` which is a part of the domain. This user is not a local administrator on the machine. The scope is restricted to the `corp.com` domain.
> 
> We have remoted into `CLIENT75` using [xfreerdp](../../../CLI-tools/linux/remote/xfreerdp.md) via the [RDP](../../../networking/protocols/RDP.md) protocol:
> `kali@kali:~$ xfreerdp /u:stephanie /d:corp.com /v:192.168.50.75`

[_PowerView_](https://powersploit.readthedocs.io/en/latest/Recon/) is a [PowerShell](../../../coding/languages/powershell.md) script created for enumerating [Active Directory](../../../computers/windows/active-directory/active-directory.md). Similar to our [LDAP-ADSI](LDAP-ADSI.md) script, PowerView uses [.NET](../../../coding/dotNET.md) classes to get the [LDAP ADsPath](../../../computers/windows/active-directory/ADSI.md#LDAP%20ADsPath) for communicating with the target domain.

Let's assume the script is already installed in `C:\Tools` and all we have to do to start using it is import it to memory:
```powershell
PS C:\Tools> Import-Module .\PowerView.ps1
```
## Enumerating Objects
For a full list of commands and functionality check out the [PowerView Usage Docs](https://powersploit.readthedocs.io/en/latest/Recon/). 
### `Get-NetDomain`
We can start by using `Get-NetDomain` which will tell us basic info about the domain:
```powershell
PS C:\Tools> Get-NetDomain

Forest                  : corp.com
DomainControllers       : {DC1.corp.com}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner            : DC1.corp.com
RidRoleOwner            : DC1.corp.com
InfrastructureRoleOwner : DC1.corp.com
Name                    : corp.com
```
### `Get-NetUser`
`Get-NetUser` automatically enumerates *all the attributes* of each user object. This produces a lot of output:
```powershell
PS C:\Tools> Get-NetUser

logoncount             : 113
iscriticalsystemobject : True
description            : Built-in account for administering the computer/domain
distinguishedname      : CN=Administrator,CN=Users,DC=corp,DC=com
objectclass            : {top, person, organizationalPerson, user}
lastlogontimestamp     : 9/13/2022 1:03:47 AM
name                   : Administrator
objectsid              : S-1-5-21-1987370270-658905905-1781884369-500
samaccountname         : Administrator
admincount             : 1
codepage               : 0
samaccounttype         : USER_OBJECT
accountexpires         : NEVER
cn                     : Administrator
whenchanged            : 9/13/2022 8:03:47 AM
instancetype           : 4
usncreated             : 8196
objectguid             : e5591000-080d-44c4-89c8-b06574a14d85
lastlogoff             : 12/31/1600 4:00:00 PM
objectcategory         : CN=Person,CN=Schema,CN=Configuration,DC=corp,DC=com
dscorepropagationdata  : {9/2/2022 11:25:58 PM, 9/2/2022 11:25:58 PM, 9/2/2022 11:10:49 PM, 1/1/1601 6:12:16 PM}
memberof               : {CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=com, CN=Domain Admins,CN=Users,DC=corp,DC=com, CN=Enterprise
                         Admins,CN=Users,DC=corp,DC=com, CN=Schema Admins,CN=Users,DC=corp,DC=com...}
lastlogon              : 9/14/2022 2:37:15 AM
...
```
#### Filtering by Attribute
If we want to filter the output so it shows specific attributes for each user account object, we can use a pipe `|` to pipe the output to `select` and select for something specific:
```powershell
PS C:\Tools> Get-NetUser | select cn,pwdlastset,lastlogon

cn            pwdlastset            lastlogon
--            ----------            ---------
Administrator 8/16/2022 5:27:22 PM  9/14/2022 2:37:15 AM
Guest         12/31/1600 4:00:00 PM 12/31/1600 4:00:00 PM
krbtgt        9/2/2022 4:10:48 PM   12/31/1600 4:00:00 PM
dave          9/7/2022 9:54:57 AM   9/14/2022 2:57:28 AM
stephanie     9/2/2022 4:23:38 PM   12/31/1600 4:00:00 PM
jeff          9/2/2022 4:27:20 PM   9/14/2022 2:54:55 AM
jeffadmin     9/2/2022 4:26:48 PM   9/14/2022 2:26:37 AM
iis_service   9/7/2022 5:38:43 AM   9/14/2022 2:35:55 AM
pete          9/6/2022 12:41:54 PM  9/13/2022 8:37:09 AM
jen           9/6/2022 12:43:01 PM  9/13/2022 8:36:55 AM
```
The above output shows us when each user *last changed their password* as well as when they *last logged into the domain*. For users who haven't changed their password in a while, there's a possibility that their current password *doesn't meet the organization's most up to date policies*.
### `Get-NetGroup`
Similar to `Get-NetUser` this will return all of the group objects in the domain. It can also be piped to select to filter for specific attributes:
```powershell
PS C:\Tools> Get-NetGroup | select cn

cn
--
...
Key Admins
Enterprise Key Admins
DnsAdmins
DnsUpdateProxy
Sales Department
Management Department
Development Department
Debug
```
This command cuts down on the output by only selecting for the `cn` (Common Name) of each group and outputting it. The CN functions as the group's name, just like it functions as a user object types *username*.
#### Enumerating a Specific Group
We can also ask `Get-NetGroup` to enumerate a specific group, and of course, pipe to `select` to further filter the output:
```powershell
PS C:\Tools> Get-NetGroup "Sales Department" | select member

member
------
{CN=Development Department,DC=corp,DC=com, CN=pete,CN=Users,DC=corp,DC=com, CN=stephanie,CN=Users,DC=corp,DC=com}
```
### `Get-NetComputer`
This module in PowerView will enumerate any computer [objects](../../../computers/windows/active-directory/objects.md) in the domain:
```powershell
PS C:\Tools> Get-NetComputer

pwdlastset                    : 10/2/2022 10:19:40 PM
logoncount                    : 319
msds-generationid             : {89, 27, 90, 188...}
serverreferencebl             : CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=com
badpasswordtime               : 12/31/1600 4:00:00 PM
distinguishedname             : CN=DC1,OU=Domain Controllers,DC=corp,DC=com
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 10/13/2022 11:37:06 AM
name                          : DC1
objectsid                     : S-1-5-21-1987370270-658905905-1781884369-1000
samaccountname                : DC1$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
whenchanged                   : 10/13/2022 6:37:06 PM
accountexpires                : NEVER
countrycode                   : 0
operatingsystem               : Windows Server 2022 Standard
instancetype                  : 4
msdfsr-computerreferencebl    : CN=DC1,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=corp,DC=com
objectguid                    : 8db9e06d-068f-41bc-945d-221622bca952
operatingsystemversion        : 10.0 (20348)
lastlogoff                    : 12/31/1600 4:00:00 PM
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=corp,DC=com
dscorepropagationdata         : {9/2/2022 11:10:48 PM, 1/1/1601 12:00:01 AM}
serviceprincipalname          : {TERMSRV/DC1, TERMSRV/DC1.corp.com, Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/DC1.corp.com, ldap/DC1.corp.com/ForestDnsZones.corp.com...}
usncreated                    : 12293
lastlogon                     : 10/18/2022 3:37:56 AM
badpwdcount                   : 0
cn                            : DC1
useraccountcontrol            : SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
whencreated                   : 9/2/2022 11:10:48 PM
primarygroupid                : 516
iscriticalsystemobject        : True
msds-supportedencryptiontypes : 28
usnchanged                    : 178663
ridsetreferences              : CN=RID Set,CN=DC1,OU=Domain Controllers,DC=corp,DC=com
dnshostname                   : DC1.corp.com
```
This is a lot of info, so we can again cut it down using `select` to select for just the [operating system](../../../computers/concepts/operating-system.md) and [DNS](../../../networking/DNS/DNS.md) hostname for each computer object:
```powershell
PS C:\Tools> Get-NetComputer | select operatingsystem,dnshostname

operatingsystem              dnshostname
---------------              -----------
Windows Server 2022 Standard DC1.corp.com
Windows Server 2022 Standard web04.corp.com
Windows Server 2022 Standard FILES04.corp.com
Windows 11 Pro               client74.corp.com
Windows 11 Pro               client75.corp.com
Windows 10 Pro               CLIENT76.corp.com
```
From the output, we've learned that there are *six computer objects* in the domain. Three of those *are servers* (as indicated by their OS), and three are likely regular clients or *"workstations"*. Additionally, one of the servers (`DC1.corp.com`) is a [Domain Controller](../../../computers/windows/active-directory/domain-controller.md) (the [Primary Domain Controller](LDAP-ADSI.md#Primary%20Domain%20Controller) as we discovered earlier).

This is useful information because we not only can identify which targets *might be weaker*, we can also see *which are oldest* and thus, more likely to be vulnerable to certain attacks.
## Enumerating Permissions
In an assessment, one of the first things we should do before [privesc](../../windows-privesc/README.md) is *strengthen our foothold*. Maintaining access *is more important* than escalating privileges, because if we lose access, it doesn't matter what privileges we gained. 

For instance, if you gain access to an AD computer as one user, compromising a second user, even if they have the same level of privilege, should be an immediate priority. You want to *maintain access* in the case that the first user changes their password, or if their account is disabled *after an admin notices suspicious activity*.

Additionally, when the time does come for privilege escalation, it does not need to be straight to Domain Admin. There may be other accounts with more privilege than your current one which you could compromise first. It may also be easier to compromise a slightly lower-privileged account first and then an admin account rather than try to compromise a Domain Admin immediately.

There may be multiple avenues to the *crown jewels* so enumerating the current user and figuring out their permissions, the groups they're in etc. is an important tactic.
### `Find-LocalAdminAccess`
This is a PowerView command which *scans the network* to find out if our *current user* has administrative permissions on any computers in the domain. The command uses the [_OpenServiceW function_](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openservicew) which connects to the [Service Control Manager](../../windows-privesc/windows-services/windows-services.md#Windows%20Services%20Overview) (SCM) on target machines.

PowerView attempts to open the SCM database using the `SC_MANAGER_ALL_ACCESS` access right. This right *requires admin privileges*, so if the connection is successful, then PowerView deems the user account has admin privileges on that target machine:
```powershell
PS C:\Tools> Find-LocalAdminAccess
client74.corp.com
```
From the output, we've learned that the current user (`stephanie`) has admin access to `client74.corp.com`. 
#### Using Credentials
You can also give the `-ComputerName` and `-Credential` flags to this command (in the case you're not logged in as the user or there is another user you want to check). Read more about that [here](https://powersploit.readthedocs.io/en/latest/Recon/Find-LocalAdminAccess/)
### `Get-NetSession`
Before chasing one rabbit down some rabbit hole, lets stop to get a better idea of how the compromised system and its users are working as a whole. One way to do this is to *figure out which users are currently logged in* and to which computers. 

PV's `Get-NetSession` does this by using the Windows APIs [`NetWkstaUserEnum`](https://learn.microsoft.com/en-us/windows/win32/api/lmwksta/nf-lmwksta-netwkstauserenum)and [`NetSessionEnum`](https://learn.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netsessionenum). The command essentially asks "for this given computer object, what sessions are currently active"?
``` powershell
PS C:\Tools> Get-NetSession -ComputerName files04

PS C:\Tools> Get-NetSession -ComputerName web04
PS C:\Tools>
```
The output above lists nothing. To be sure that both computers have no current sessions, we can add the `-Verbose` flag:
```powershell
PS C:\Tools> Get-NetSession -ComputerName files04 -Verbose
VERBOSE: [Get-NetSession] Error: Access is denied

PS C:\Tools> Get-NetSession -ComputerName web04 -Verbose
VERBOSE: [Get-NetSession] Error: Access is denied
```
For both computers, `stephanie` does not have permission to run `NetSessionEnum` (like PowerView is trying to do). This is because the `NetSessionEnum` API *requires admin privileges*. Let's see what we get back for `client74` since we know that `stephanie` has admin access there:
```powershell
PS C:\Tools> Get-NetSession -ComputerName client74

CName        : \\192.168.50.75
UserName     : stephanie
Time         : 8
IdleTime     : 0
ComputerName : client74
```
We have more output, but something is off. The IP address listed as the `CName` *is not the IP address of `client74`*. It's actually the address of `client75`, the computer *we're running our commands from*. The explanation for this behavior comes from the `NetSessionEnum` API.
#### Digging into `NetSessionEnum`
Reading through the [docs for `NetSessionEnum`](https://learn.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netsessionenum) there are five query "levels":
- 0: only returns the name of the computer establishing the connection
- 1: returns the name of the computer, user, open files, pipes, and devices on the computer (*requires admin rights*)
- 2: in addition to level 1, returns the client type and how the user session was established (*requires admin rights*)
- 10: returns computer name, user name, active and idle times - *default level used by PowerView*
- 502: returns computer name, user name, open files, pipes, devices on the computer, transport client name
##### `SrvsvcSessionInfo` Registry Key
The permissions required to use `NetSessionEnum` are *defined in the `SrvsvcSessionInfo` registry key* which is located in the `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity` hive.

We can use `Get-Acl` with the `-Path` flag to *check the permissions listed for `NetSessionEnum`* in the registry key/hive. `Get-Acl` is a PS cmdlet which *retrieves the permissions* for the object we define using `-Path`:
```powershell
PS C:\Tools> Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl

Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\
Owner  : NT AUTHORITY\SYSTEM
Group  : NT AUTHORITY\SYSTEM
Access : BUILTIN\Users Allow  ReadKey
         BUILTIN\Administrators Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  FullControl
         CREATOR OWNER Allow  FullControl
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  ReadKey
```
From the output, it appears `stephanie` should have permission to use `NetSessionEnum` but (if I'm understanding OffSec's explanation correctly) the groups defined by the system (`BUILTIN` `NT AUTHORITY` `CREATOR OWNER` and `APPLICATION PACKAGE AUTHORITY`) *do NOT allow `NetSessionEnum`* to enumerate the registry key *from a remote client*. 

In short, on Windows 11 (the OS of our executing machine) `NetSessionEnum` will *not be able to obtain* the info we want. This is because Microsoft at some point *changed the registry hive* (mentioned above).
##### Capability SIDs
The output also shows a long string at the end which, according to [Microsoft's documentation](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/sids-not-resolve-into-friendly-names) is a *Capability SID*.  Capability SIDs are [tokens](../../windows-privesc/security-mechanisms/access-tokens.md) of authority which are *unforgeable*. They grant access to various resources to either a "Windows component" or "Universal Windows Application." 

--- 
> [!Resources]
> - [PowerView.ps1 Script (GitHub)](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
> - [PowerView Usage Docs](https://powersploit.readthedocs.io/en/latest/Recon/)
> - [_OpenServiceW function_](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openservicew)
> - [`NetWkstaUserEnum`](https://learn.microsoft.com/en-us/windows/win32/api/lmwksta/nf-lmwksta-netwkstauserenum)
> - [`NetSessionEnum`](https://learn.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netsessionenum)
> - [_PsLoggedOn_](https://learn.microsoft.com/en-us/sysinternals/downloads/psloggedon)
> - [_SysInternals Suite_](https://learn.microsoft.com/en-us/sysinternals/)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.
