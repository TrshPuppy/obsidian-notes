
# Setting Up Users, Groups & Policies
> This is all done in the context of creating a vulnerable AD environment, i.e. it doesn't cover everything.
> The values I'm using for:
> - Domain controller: `TRASH-DC`
> - Domain: `LANDFILL`

In the domain controller (AD Server) we can add users and groups using Server Manager. Just click tools --> 'Active Directory Users & Computers':
![](/PNPT-pics/active-directory-1.png)
![](PNPT/PNPT-pics/active-directory-1.png)
## Creating Users
### Creating an Administrator
The easiest way to create an Admin is to right click and copy the existing, default admin. This will copy all of the characteristics of the Admin, *including the groups they're in* into the new user.
![](PNPT/PNPT-pics/active-directory-2.png)
![](/PNPT-pics/active-directory-2.png)
### Creating Service Accounts
A common vulnerability found in AD is when a network admin *creates an administrator account* to be used as a service account. Service accounts (which are used to run services such as [SQL](/coding/languages/SQL.md)) *do not need admin privileges* most of the time. But this is still a common practice.

For our AD lab, we can make a SQL Service account by copying the Admin user again, and naming it 'SQLService'. We're making this account intentionally vulnerable, so to make it worse, add a description like 'password = <whatever password you set\>'. This is another common vulnerable practice found in AD environments.
### Creating Regular Users
To create a regular user using Server Manager, just right click in the white space of the 'Active Directory Users and Computers' prompt window, then click New --> User.
## Creating File Shares
In Server Manager, click 'File and Storage Services' in the left hand panel, then click 'Shares'. At the top right corner of the Shares window, click 'Tasks' --> 'New Share'.
### Lab Share
Click on 'SMB Share - Quick'. Verify the Server is our lab server, and the path is inn the C: drive. Name the share whatever you like, keep the next default preferences ('Allow caching of share'). Keep the default permissions and then confirm.
## Creating an SPN for `SQLService`
Next we want to set up an [SPN](/computers/windows/active-directory/setspn.md) for our SQL service account. We'll do this in command prompt using the [`setspn`](/computers/windows/active-directory/setspn.md) command:
```powershell
setspn -s SQLService/LANDFILL.local TRASH-DC
```
![](PEH/active-directory/active-directory-3.png)
![](/PEH/active-directory/active-directory-3.png)
### Confirming our new SPN
To make sure we successfully set up the SPN for `SQLService` we can use the `setspn` command again with a `-L` flag:
```powershell
setspn -T LANDFILL.local -Q */*
```
![](PNPT/PNPT-pics/active-directory-4.png)
![](/PNPT-pics/active-directory-4.png)
## Group Policy Management
On our AD Server, we can search for 'group policy management' in the taskbar to find and open the Group Policy Manager app. We're going to make one called 'Disable Windows Defender' so we can get Windows Defender out of the way in order to learn how AD is vulnerable (without it).
![](PNPT/PNPT-pics/active-directory-5.png)
![](/PNPT-pics/active-directory-5.png)
In order to create a new Group Policy, right click on our domain name and choose the following:
![](/PNPT-pics/active-directory-6.png)
![](PNPT/PNPT-pics/active-directory-6.png)
Let's create a GPO called *Disable Windows Defender*:
![](/PNPT-pics/active-directory-7.png)
![](PNPT/PNPT-pics/active-directory-7.png)
Once that's created, right click on the new GPO and click 'Edit', then traverse through these directories until you find 'Microsoft Defender Antivirus' *or* 'Windows Defender Antivirus':
![](/PNPT-pics/active-directory-8.png)
![](PNPT/PNPT-pics/active-directory-8.png)
Once you've found it, go into that folder and click 'Turn Off Microsoft Defender Antivirus.' Then click 'Enabled' --> 'Apply' --> 'Okay'. Once that's done, the last thing you should do is go back to the 'Group Policy Manager' app, right click the new 'Disable Microsoft Defender' GPO and select *'Enforced'*.
### 'Enforced'
When a policy is Enforced it means that anytime a user or computer joins the domain, *it will inherit this policy*.

> [!Resources]
> - My non-PNPT notes, referenced throughout, all of which can be found [here](https://github.com/TrshPuppy/obsidian-notes)
