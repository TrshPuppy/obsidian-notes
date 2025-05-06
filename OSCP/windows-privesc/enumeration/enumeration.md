
# Situational Awareness
Once we've compromised a system, we need to gather information about it *before attempting to privesc.* This will help us find vectors for escalating our priviliges (in cases where we've landed on the box as an unprivileged user/account).

The pieces of information to focus on include:
- username and hostname
- group membership of our current user
- other existing users and groups
- [operating-system](../../../computers/concepts/operating-system.md) info including version and architecture
- network information
- installed applications
- running processes
All of these should be enumerated so we can get a good idea of how to further target the system and privilege escalate. 
## User, Hostname & Group Enumeration
> [!Note]
> For these notes the assumption is we've used a client-side attack to gain access via a [bind-shell](../../../cybersecurity/TTPs/exploitation/bind-shell.md) running on port `44444`. The system is called `CLIENTWK220`, and the account we've compromised is `dave`.
### `whoami`
`whoami` is a common command-line tool found on both [Windows](../../../computers/windows/README.md) and Linux machines. We can use this to see both the username and the hostname:
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

`dave` is also a member of `BUILTIN\Remote Desktop Users` which indicates he might be able to connect *via [RDP](../../../networking/protocols/RDP.md)* to this system.

The remaining groups are *standard* and non-privileged, like `Everyone` and `BUILTIN\Users`. 
### `net user` & `Get-LocalUser`
We can use the `net` command with the `user` module to enumerate other users and groups present on the system. We can also use the `Get-LocalUser` cmdlet (from [powershell](../../../coding/languages/powershell.md)) to get a list of *all local users* on the system:
```powershell
PS C:\Users\dave> Get-LocalUser
Get-LocalUser
Name                                Description                                       ----                                ----------- 
Administrator      False   Built-in account for administering the computer/domain
BackupAdmin        True
dave               True    dave 
daveadmin          True 
DefaultAccount     False   A user account managed by the system.
Guest              False   Built-in account for guest access to the computer/domain
offsec             True
steve              True
... 
```
From this listing we can see that the *default `Administrator` account is disabled*, but there is one other regular user (`steve`) and two presumably admin accounts: `BackupAdmin` and `daveadmin`. We can assume that `daveadmin` is the *privileged account* for `dave` which is a common practice by SysAdmins (the non-privileged account is usually used for day to day tasks while the privileged one is for admin tasks). 
### `net localgroup` & `Get-LocalGroup`
These two commands will list groups local on the system with `Get-LocalGroup` being the powershell cmdlet:
```powershell
PS C:\Users\dave> Get-LocalGroup
Get-LocalGroup
Name                                Description                                       ----                                ----------- 
adminteam                  Members of this group are admins to all workstations on the second floor
BackupUsers 
helpdesk
...
Administrators                      Administrators have complete and unrestricted access to the computer/domain
...
Remote Desktop Users                Members in this group are granted the right to logon remotely
...  
```
Non-standard groups in this listing are `BackupUsers`, `helpdesk` and `adminteam`. 
#### Standard Groups
The standard groups in the listing above include some common ones:
- `Backup Operators`: can backup and restore *all files* on the computer, even ones they *don't have permission for*
- `Remote Desktop Users`: can access the system using [RDP](../../../networking/protocols/RDP.md)
	- `Remote Management Users`: can access the system using *[WinRM](../../../computers/windows/WinRM.md)*
- `Administrators`
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
## System & Network Enumeration
Now that we have info for the users, groups, and the hostname of the machine we compromised, it's time to enumerate the system itself including its architecture, operating system and running applications.
### `systeminfo`
The `systeminfo` command tells us the operating system, its version and the architecture its running on:
```powershell
PS C:\Users\dave> systeminfo
systeminfo

Host Name:                 CLIENTWK220
OS Name:                   Microsoft Windows 11 Pro
OS Version:                10.0.22621 N/A Build 22621
...
System Type:               x64-based PC
...
```
We can see that the current system is running Windows 11 Pro and the build number (`22621`) tells us that the version thats running is *22H2 of Windows 11*. We can also see that system is running on a *64-bit architecture*. This is useful to know if we plan on building or running any binaries on the system since *they'll have to be 64-bit applications* (instead of 32-bit). 
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
- the system does not get leased an [IP address](../../../networking/OSI/3-network/IP-addresses.md) from [DHCP](../../../networking/protocols/DHCP.md) (it was set manually)
- the DNS server, gateway, and [Subnet Mask](../../../PNPT/PEH/networking/subnetting.md#Subnet%20Mask)
- the [MAC address](../../../networking/OSI/2-datalink/MAC-addresses.md)
All of this information will be useful if we try to *move laterally* to other systems on the network.
### `route print`
This command will display the [routing-table](../../../networking/routing/routing-table.md) which contains *all of the routes* known to the system. We can use the output from `route print` to determine possible *attack vectors* to other systems and networks:
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
### `netstat`
[netstat](../../../CLI-tools/windows/netstat.md) is a command line tool on both Windows machines which we can use to display active [TCP](../../../networking/protocols/TCP.md) connections, listening [ports](../../../networking/routing/ports.md), ethernet stats, IP routing tables and stats for both [IPv4 and IPv6](../../../networking/OSI/3-network/IP-addresses.md#IPv4%20vs%20IPv6). Without giving any parameters, it lists active TCP connections. But with the parameters `-ano`, we can see all active TCP connections as well as TCP and [UDP](../../../networking/protocols/UDP.md) ports (with `-n` disabling name resolution and `-o` showing the process ID for each connection):
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
In this ouptut, we can see that ports `80` and `443` on the system are listening for connections. This usually indicates that a web server is hosted and running on the system. There is also a [mysql](../../../CLI-tools/linux/mysql.md) server likely running on port `3306`. We can also see our [netcat](../../../cybersecurity/TTPs/exploitation/tools/netcat.md) connection (our [bind-shell](../../../cybersecurity/TTPs/exploitation/bind-shell.md)) running on port `44444` and an RDP connection running on port `3389`. 

The RDP connection specifically indicates that *we might not be the only user connected to this machine*. 
### Installed Applications
To query for 32-bit and 64-bit applications installed on the system, we can use the `Get-ItemProperty` cmdlet. To ask for all of the installed applications, we're going to ask `Get-ItemProperty` to list all of the values from the *[Uninstall Registry Key](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key?redirectedfrom=MSDN)*

If we pipe the output to `select` with the `displayname` flag, we can see a list of the names for all of the applications:
```powershell
PS C:\Users\dave> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname 

displayname                                                       
-----------                                                       
FileZilla 3.63.1                                                  
KeePass Password Safe 2.51.1                                   
Microsoft Edge                                                    
Microsoft Edge Update                                             
Microsoft Edge WebView2 Runtime                                   
                                                                  
Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.28.29913
Microsoft Visual C++ 2019 X86 Additional Runtime - 14.28.29913    
Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.28.29913       
Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.28.29913

PS C:\Users\dave> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

DisplayName                                                   
-----------                                                   
7-Zip 21.07 (x64)                                              
XAMPP                                                         
VMware Tools                                                  
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29913
Microsoft Update Health Tools                                 
Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.28.29913   
Update for Windows 10 for x64-based Systems (KB5001716) 
```
The first registry key `HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall` will list all of the *32-bit* installed applications. The second (`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`) will list all of the *64-bit ones*. 

From the output, the only *non-standard* applications installed are FileZilla (an [FTP](../../../networking/protocols/FTP.md) client), KeePass (a password manager), 7-Zip and XAMPP.
#### Checking Other Directories
In case some applications were installed improperly, we should also check the `Program Files` directories for installed files. The 32-bit and 64-bit directories are located on the `C:\` drive. We should also check the `Downloads` folder.
### Running Processes
We should also check for which processes *are actually running* on the compromised system. We can do that with `Get-Process`:
```powershell
PS C:\Users\dave> Get-Process
Get-Process
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName                 
-------  ------    -----      -----     ------     --  -- -----------                 
     58      13      528       1088       0.00   2064   0 access
...                                                  
    369      32     9548      31320              2632   0 filezilla                   
...                                         
    188      29     9596      19716              3340   0 httpd                                 
    486      49    16528      23060              4316   0 httpd
...                                                   
    205      17   210736      29228              3508   0 mysqld
...                                     
    982      32    83696      13780       0.59   2836   0 powershell
    587      28    65628      73752              9756   0 powershell
...
```
In the listing we can see a few running processes and their process IDs. For example, our bind shell is running w/ process ID `2064`, and our current powershell session is running w/ the ID `9756`. Referring back to our `netstat` command output, this listing confirms Apache running as `httpd` w/ ID `4316` and `mysqld` running w/ ID `4316`. Both of these were likely started through XAMPP.

> [!Resources]
> - [_net user_](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771865\(v=ws.11\))
> - [_Get-LocalGroup_](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localgroup?view=powershell-5.1)
> - [_Get-LocalUser_](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localuser?view=powershell-5.1)
> - [_ipconfig_](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig)
> - [Microsoft: Netstat](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat)
> - [Microsoft DevBlogs: Use PowerShell to Find Installed Software](https://devblogs.microsoft.com/scripting/use-powershell-to-find-installed-software/)
> - [Microsoft: Uninstall Registry Key](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key?redirectedfrom=MSDN)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.

