---
aliases:
  - enumerating AD
---
# Enumerating Active Directory w/ `net`
> [!Note]
> For these notes, the following *scenario* applies: we're enumerating the `corp.com` domain. We've obtained user credentials to a domain user through a successful phishing attack. The user we have access to is `stephanie` who has remote desktop permissions on a Windows 11 machine `CLIENT75` which is a part of the domain. This user is not a local administrator on the machine. The scope is restricted to the `corp.com` domain.
> 
> We have remoted into `CLIENT75` using [xfreerdp](../../../CLI-tools/linux/remote/xfreerdp.md) via the [RDP](../../../networking/protocols/RDP.md) protocol:
> `kali@kali:~$ xfreerdp /u:stephanie /d:corp.com /v:192.168.50.75`

We're going to start by enumerating *user and group* information using the `net` command and its `user` and `group` subcommands. 
## `net user`
The `/domain` flag tells `net user` to enumerate *domain users* rather than *local users*:
```powershell
C:\Users\stephanie>net user /domain
The request will be processed at a domain controller for domain corp.com.

User accounts for \\DC1.corp.com

-------------------------------------------------------------------------------
Administrator            dave                     Guest
iis_service              jeff                     jeffadmin
jen                      krbtgt                   pete
stephanie
The command completed successfully.
```
According to the output, the there is a `jeff` account and a `jeffadmin` account. Administrators will commonly add *suffixes or prefixes* to usernames to identify the account by its function. So, we should check if `jeffadmin` is an administrative account:
### `net user` w/ a specific user
```powershell
C:\Users\stephanie>net user jeffadmin /domain
The request will be processed at a domain controller for domain corp.com.

User name                    jeffadmin
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            9/2/2022 4:26:48 PM
Password expires             Never
Password changeable          9/3/2022 4:26:48 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   9/20/2022 1:36:09 AM

Logon hours allowed          All

Local Group Memberships      *Administrators
Global Group memberships     *Domain Users         *Domain Admins
The command completed successfully.
```
At the bottom of the output, we can see that `jeffadmin` is a part of the *Domain Admins* group. If we can compromise this account, it will *elevate our privileges* to that of a domain administrator.
## `net group`
Next, we can use `net` and its `group` subcommand to enumerate groups. The `/domain` flag will again enumerate *groups in the domain* rather than local groups:
```powershell
C:\Users\stephanie>net group /domain
The request will be processed at a domain controller for domain corp.com.

Group Accounts for \\DC1.corp.com

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*Debug
*Development Department
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*Key Admins
*Management Department
*Protected Users
*Read-only Domain Controllers
*Sales Department
*Schema Admins
The command completed successfully.
```
Most of the groups in the output are *installed by default*. The custom groups in the listing include:
- Development Department
- Management Department
- Sales Department
These custom groups were likely created *by an administrator*. Let's enumerate one of them using `net group` again.
### `net group` w/ specific group
```powershell
PS C:\Tools> net group "Sales Department" /domain
The request will be processed at a domain controller for domain corp.com.

Group name     Sales Department
Comment

Members

-------------------------------------------------------------------------------
pete                     stephanie
The command completed successfully.
```

> [!Resources]
> - [_Remote Server Administration Tools_](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remote-server-administration-tools) (RSAT)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.
> 