
# Windows Enumeration
The first thing you should do when you gain access to a Windows machine is enumeration.
## Users
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
### `whoami`
`whoami` is a common command-line tool found on both [Windows](../../computers/windows/README.md) and Linux machines. We can use this to see both the username and the hostname:
```powershell
kali@kali:~$ nc 192.168.50.220 4444
Microsoft Windows [Version 10.0.22000.318]
(c) Microsoft Corporation. All rights reserved.

C:\Users\dave>whoami
whoami
clientwk220\dave

C:\Users\dave>
```
As the first command we run, it also *proves we have command execution* as the user `dave`. The hostname is useful because you can use it to *infer what kind of system* you're on. In this case, it's clear we're on a client system and not a server. Sometimes the hostname will also hint at the purpose of the system or what applications are running on it. 
#### `whoami /groups`
We can also use `whoami` to check which groups `dave` is a member of. On windows we give the switch `/groups`:
```powershell
C:\Users\dave> whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                             Type             SID                                            Attributes                                        
====================================== ================ ============================================== ==================================================
Everyone                             Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
CLIENTWK220\helpdesk                 Alias            S-1-5-21-2309961351-4093026482-2223492918-1008 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users         Alias            S-1-5-32-555                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                   Well-known group S-1-5-3                                        Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
... 
```
From this listing we can see that one of the groups `dave` belongs to is the `helpdesk` group. This might mean he has *additional permissions and access* compared to regular users (since he is likely part of the organization's help desk staff). 

`dave` is also a member of `BUILTIN\Remote Desktop Users` which indicates he might be able to connect *via [RDP](../../networking/protocols/RDP.md)* to this system.

The remaining groups are *standard* and non-privileged, like `Everyone` and `BUILTIN\Users`. 
### `net user`
Similar to the cmdlet `Get-LocalUser`.
### `Get-LocalUser`
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
Each user has an [SID](../../OSCP/windows-privesc/security-mechanisms/SID.md):
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
#### Example: sorting by `PasswordRequired` property
```PowerShell
get-localuser | where-object -property passwordRequired -like false

Name           Enabled Description
----           ------- -----------
DefaultAccount False   A user account managed by the system.
duck           True
duck2          True
Guest          False   Built-in account for guest access to the computer/domain
```
## Groups
### `net localgroup`
Is one command we can use similar to the [powershell](../../coding/languages/powershell.md) cmdlet `Get-LocalGroup`.
### `Get-LocalGroup`
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
### `Get-LocalGroupMember`
`Get-LocalGroupMember` is a powershell cmdlet which we can use to review information *for specific groups*. For example, lets use it to review the `adminteam` and `Administrators` groups and their members:
```powershell
PS C:\Users\dave> Get-LocalGroupMember adminteam
Get-LocalGroupMember adminteam

ObjectClass Name                PrincipalSource
----------- ----                ---------------
User        CLIENTWK220\daveadmin Local 

PS C:\Users\dave> Get-LocalGroupMember Administrators
Get-LocalGroupMember Administrators

ObjectClass Name                      PrincipalSource
----------- ----                      ---------------
User        CLIENTWK220\Administrator Local          
User        CLIENTWK220\daveadmin     Local
User        CLIENTWK220\backupadmin     Local  
User        CLIENTWK220\offsec        Local
```
From this we can see that `daveadmin` is the only member of the `adminteam` group.  Another interesting thing to note is `adminteam` *is not listed in the local `Administrators` group*. From the previous `Get-LocalGroup` listing, we know that members of the `adminteam` group are "are admins to all workstations on the second floor" (per the description). So our current system must not be part of that second floor, but we may be able to use this info later as we move laterally through the network. 

Regarding `Administrators`, we've identified at least two *high value targets*: `daveadmin` and `backupadmin` are both members in the `Administrators` group.
## Network
### `netstat`
[netstat](../../CLI-tools/windows/netstat.md) is a command line tool on both Windows machines which we can use to display active [TCP](../../networking/protocols/TCP.md) connections, listening [ports](../../networking/routing/ports.md), ethernet stats, IP routing tables and stats for both [IPv4 and IPv6](../../networking/OSI/3-network/IP-addresses.md#IPv4%20vs%20IPv6). Without giving any parameters, it lists active TCP connections. But with the parameters `-ano`, we can see all active TCP connections as well as TCP and [UDP](../../networking/protocols/UDP.md) ports (with `-n` disabling name resolution and `-o` showing the process ID for each connection):
```powershell
PS C:\Users\dave> netstat -ano
netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       3340
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1016
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       3340
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3306           0.0.0.0:0              LISTENING       3508
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1148
  TCP    192.168.50.220:139     0.0.0.0:0              LISTENING       4
  TCP    192.168.50.220:3389    192.168.48.3:33770     ESTABLISHED     1148
  TCP    192.168.50.220:44444    192.168.48.3:58386     ESTABLISHED     2064
...
```
### `route print`
This command will display the [routing-table](../../networking/routing/routing-table.md) which contains *all of the routes* known to the system. We can use the output from `route print` to determine possible *attack vectors* to other systems and networks:
```powershell
PS C:\Users\dave> route print
route print
===========================================================================
Interface List
  4...00 50 56 95 01 6a ......vmxnet3 Ethernet Adapter
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0   192.168.50.254   192.168.50.220    271
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
     192.168.50.0    255.255.255.0         On-link    192.168.50.220    271
   192.168.50.220  255.255.255.255         On-link    192.168.50.220    271
   192.168.50.255  255.255.255.255         On-link    192.168.50.220    271
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link    192.168.50.220    271
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link    192.168.50.220    271
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0   192.168.50.254  Default 
===========================================================================

IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
  1    331 ::1/128                  On-link
  4    271 fe80::/64                On-link
  4    271 fe80::1b30:4f11:8789:866a/128
                                    On-link
  1    331 ff00::/8                 On-link
  4    271 ff00::/8                 On-link
===========================================================================
Persistent Routes:
  None
```
This output *doesn't reveal any routes to unknown networks*, but it's still a valuable thing to check during penetration tests.
### `ipconfig /all`
`ipconfig` is a command on Windows which you can use to view info about and configure network interfaces on the machine. The `/all` switch will list all of the network interfaces with information pertaining to each:
```powershell
PS C:\Users\dave> ipconfig /all
ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : clientwk220
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-8A-80-16
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::cc7a:964e:1f98:babb%6(Preferred) 
   IPv4 Address. . . . . . . . . . . : 192.168.50.220(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.254
   DHCPv6 IAID . . . . . . . . . . . : 234901590
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-2A-3B-F7-25-00-50-56-8A-80-16
   DNS Servers . . . . . . . . . . . : 8.8.8.8
   NetBIOS over Tcpip. . . . . . . . : Enabled
```
From this output, we've learned a few interesting facts:
- the system does not get leased an [IP address](../../networking/OSI/3-network/IP-addresses.md) from [DHCP](../../networking/protocols/DHCP.md) (it was set manually)
- the DNS server, gateway, and [Subnet Mask](../../PNPT/PEH/networking/subnetting.md#Subnet%20Mask)
- the [MAC address](../../networking/OSI/2-datalink/MAC-addresses.md)
All of this information will be useful if we try to *move laterally* to other systems on the network.
### IP Address
```Powershell
Get-NetIPAddress
```
### Ports
```
Get-NetTCPConnection
```
## Installations/ Patches
### Hot-Fixes
```
Get-HotFix
```
### CIM Instance
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
## Backup files
Backup files are normally saves with the `.bak` extension. To find a specific backup file:
```powershell
Get-ChildItem -Recurse -ErrorAction SilentlyContinue -Include *.bak* -File

```
## Running Processes
```
Get-Process
```
## Drive Ownership
```
Get-Acl C:/
```

> [!Related]
> - [My notes on enumerating Windows from OSCP](../../OSCP/windows-privesc/enumeration/enumeration.md)
