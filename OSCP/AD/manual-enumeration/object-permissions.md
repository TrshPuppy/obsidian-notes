---
aliases:
  - ACLs
---
# Enumerating Object Permissions
[AD objects](../../../computers/windows/active-directory/objects.md) can have sets of permissions applied to them with multiple [_Access Control Entries_](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-entries) (ACEs). Each ACE defines whether access to the object is denied or allowed. These ACEs make up the [_Access Control List_](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists) (ACL). 
## Basic Flow
When a domain user attempts to access a specific object (a share for example), the target object (the share) will go through a validation process to determine if the user has permissions to access the share based on the ACL. The verification process happens in two steps:
1. The user sends an *access token* made up of the user's identity and permissions
2. The target object *validates the token* against the ACL/ list of permissions
If the ACL allows the user to access the share, then access is granted. Otherwise its denied.
## Permission Types
AD uses a lot of [different permission types](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-and-access-masks). From an attacking perspective, there are a few specific ones we're interested in:
- `GenericAll`: Full permissions on an object
- `GenericWrite`: Edit certain attributes on the object
- `WriteOwner`: Change ownership of the object
- `WriteDACL`: Edit ACEs applied to the object
- `AllExtendedRights`: Change password, reset password, etc.
- `ForceChangePassword`: Password change for the object
- `Self` (Self Membership): Add yourself to a group (for example)
`GenericAll` is the highest access permission you can have over an object.
## Enumerating ACEs
We can use [PowerView](../../../cybersecurity/TTPs/actions-on-objective/tools/PowerView.md) to enumerate ACEs by using the `Get-ObjectAcl` module. For example, to enumerate the current user's (`stephanie`) ACEs (the ACEs applied to the user object), we can use the `-Identity` flag:
```powershell
PS C:\Tools> Get-ObjectAcl -Identity stephanie

...
ObjectDN               : CN=stephanie,CN=Users,DC=corp,DC=com
ObjectSID              : S-1-5-21-1987370270-658905905-1781884369-1104
ActiveDirectoryRights  : ReadProperty
ObjectAceFlags         : ObjectAceTypePresent
ObjectAceType          : 4c164200-20c0-11d0-a768-00aa006e0529
InheritedObjectAceType : 00000000-0000-0000-0000-000000000000
BinaryLength           : 56
AceQualifier           : AccessAllowed
IsCallback             : False
OpaqueLength           : 0
AccessMask             : 16
SecurityIdentifier     : S-1-5-21-1987370270-658905905-1781884369-553
AceType                : AccessAllowedObject
AceFlags               : None
IsInherited            : False
InheritanceFlags       : None
PropagationFlags       : None
AuditFlags             : None
...
```
There is a lot of output because we've enumerated all of the ACEs that grants or denies some permission to `stephanie`. However, the ones we are mostly interested in are:
- `ObjectSID`
- `ActiveDirectoryRights`
- `SecurityIdentifier`
`ObjectSID` and `SecurityIdentifier` are both [security identifiers](../../windows-privesc/security-mechanisms/SID.md) (unique identifiers which represent objects in AD). The values of both are difficult to read. So we can use PowerView's `ConvertSidToName` to make them more readable:
```powershell
PS C:\Tools> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
CORP\stephanie
```
So, the value of `ObjectSID` is `CORP\stephanie`. If we convert `SecurityIdentifier` this will tell us *who has the `ReadPorpery` permission* over the `stephanie` user object (the `ReadProperty` permission is the value of `ActiveDirectoryRights` in the output):
```powershell
PS C:\Tools> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-553
CORP\RAS and IAS Servers
```
According to the output, the SID in `SecurityIdentifier` belongs to the default AD group [_RAS and IAS Servers_](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#ras-and-ias-servers). So, in summary, the RAS and IAS Servers group has `ReadProperty` access rights to the `stephanie` user object
### Filtering the output
Let's say we want to use `Get-ObjectAcl` to select for the three properties above for an active directory group we come across called `Management Departmet`. We could filter the output using the `-eq` flag and then pipe it to select:
```powershell
PS C:\Tools> Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

SecurityIdentifier                            ActiveDirectoryRights
------------------                            ---------------------
S-1-5-21-1987370270-658905905-1781884369-512             GenericAll
S-1-5-21-1987370270-658905905-1781884369-1104            GenericAll
S-1-5-32-548                                             GenericAll
S-1-5-18                                                 GenericAll
S-1-5-21-1987370270-658905905-1781884369-519             GenericAll
```
If we use `Conver-SidToName` on the SIDs from the output, we get this:
```powershell
PS C:\Tools> "S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
CORP\Domain Admins
CORP\stephanie
BUILTIN\Account Operators
Local System
CORP\Enterprise Admins
```
In the output we can see that *`stephanie` has `GenericAll` permission on the `Management Department` group object*. With this permission, we can add `stephanie` to the group:
```powershell
PS C:\Tools> net group "Management Department" stephanie /add /domain
The request will be processed at a domain controller for domain corp.com.

The command completed successfully.
``` 
If it worked, then we should see that when we use `Get-NetGroup`:
```powershell
PS C:\Tools> Get-NetGroup "Management Department" | select member

member
------
{CN=jen,CN=Users,DC=corp,DC=com, CN=stephanie,CN=Users,DC=corp,DC=com}
```


> [!Resources]
> - [_Access Control Entries_](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-entries)
> - [_Access Control List_](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists)
> - [Microsoft Permissions](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-and-access-masks)
> - [_RAS and IAS Servers_](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#ras-and-ias-servers)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.