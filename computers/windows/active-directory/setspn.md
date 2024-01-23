
# `setspn` Command
The `setspn` command can be used on installations of Windows Server 2008 and 2012. This command reads, modifies and/ or deletes the *Service Principal Names* directory property for an [Active Directory](/computers/windows/active-directory/active-directory.md) service account (like an [SQL](/coding/languages/SQL.md) service account for example). 

`setspn` is available to use for accounts which have the Active Directory Domain Services (AD DS) server role installed. In order to use it, it has to be run *in a terminal w/ elevated privileges.*
## Service Principal Names
SPNs are used to locate principal names for running services. They're set up when the computer joins a domain and has services installed on it. However, if a computer name is changed *the SPNs will also have to change* for the services running on it.
### Authentication
In Active Directory, SPNs are built off the DNS host name. They're *used for authentication* b/w clients and the server hosting the service. When a client wants to connect to a service, it finds the account w/ the associated SPN.
### Format
When working w/ SPNs and referring to them on the CLIs, you have to use the correct format: `<serviceclass>/<host>:<port>/<servicename>`. In the following examples, a server named `WS2003A` is providing [RDP](/networking/protocols/RDP.md) services to over port `3389`. Therefore, the following two SPNs are registered in its AD computer object:
- `TERMSRV/WS2003A`
- `TERMSRV/WS2003A.cpandl.com`
### Delegating SPN Modification Authority
Only user accounts with the **Validated write to service principal name** permission are allowed to configure and modify SPNs. In order to grant these permissions to a user account, your account must be in the Domain Admins group (at least).

From the AD GUI, granting permissions to another user account goes as follows:
1. Open Active Directory Users and Computers.    
    To open Active Directory Users and Computers, click **Start**, click **Run**, type **dsa.msc**, and then press ENTER.    
2. Click **View**, and verify that the **Advanced Features** check box is selected.    
3. Click **Advanced Features**, if it is not selected.    
    If the domain to which you want to allow a disjoint namespace does not appear in the console, take the following steps:    
    1. In the console tree, right-click Active Directory Users and Computers, and then click **Connect to Domain**.        
    2. In the **Domain** box, type the name of the Active Directory domain to which you want to allow the disjoint namespace, and then click **OK**.        
        As an alternative, you can use the **Browse** button to locate the Active Directory domain.        
4. In the console tree, right-click the node that represents the domain to which you want to allow a disjoint namespace, and then click **Properties**.    
5. On **Security** tab, click **Advanced**.    
6. On the **Permissions** tab, click **Add**.    
7. In **Enter the object name to select**, type the group or user account name to which you want to delegate permission, and then click **OK**.    
8. Configure the **Apply onto** box for **Computer objects**.    
9. At the bottom of the **Permissions** box, select the **Allow** check box that corresponds to the **Validated write to service principal name** permissions, and then click **OK** on the three open dialog boxes to confirm your changes.    
10. Close Active Directory Users and Computers.
> [Microsoft: Setspn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11))
## `setspn` Usage
### Viewing SPNs
To see all the SPNs registered w/ a computer's AD, use `-l` *or* `-L`:
```powershell
setspn -l <hostname>
# Ex:
setspn -l WS2003A
```
### Resetting SPNs
If the SPNs listed for your computer appear to have incorrect names, you can reset them *to default SPNs* using `-r`.
```powershell
setspn -r <hostname>
```
The output will *confirm* whether you were successful.
### Adding SPNs
To add an SPN for a service:
```powershell
setspn -s <service>/<name> <hostname>
```
For example, if you have a [domain controller](/computers/windows/active-directory/domain-controller.md) called `TRASH-DC` in a domain called `LANDFILL`, and you wanted to add an SPN for the service account called `SQLService`, your command would look like this:
```powershell
setspn -s SQLService/LANDFILL.local TRASH-DC
```
### Deleting SPNs
Use the `-d` flag:
```powershell
setspn -d <service>/<name> <hostname>
```
### Other Options/ Tips:
- `-Q` can be used to query for SPNs: `setspn -Q SPN`
- `-F` perform queries at the forest level (instead of domain level)

> [!Resources]
> [Microsoft: Setspn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11))
