INIT
# Group Policy Object
A group policy represents policy settings in either a local file system or in an [AD](active-directory.md) Domain Services. Group Policy Objects (GPO) encapsulate or contain group policy settings. GPOs are *virtual collections* of policy settings, security permissions, and scope of management (SOM) which can be applied to users and computers in AD.

GPOs have *unique names*, such as [GUIDs](objects.md#GUIDs).
## How Group Policy Works
For computers, group policies are applied *when the computer starts*. For users, group policy is assigned *at sign in*. 
### Organizational Unit
Organizational Units (OUs) are the *lowest level of AD container which can have a group policy assigned to it*. Most GPOs are assigned at the OU level. Some, like password policies, are applied *at the domain level*. Additionally, they can be applied *at the site level* but that's more rare.
### Types of GPOs
#### Local Group Policy Objects
A collection of group policies that apply to the local computer and users.
#### Non-local
GPOs which apply to Windows computers/ users *once they're linked* to AD objects like domains, sites or OUs
#### Starter
Templates for Group Policy settings. Admins use them to create *pre-configured groups of settings* as the baselines for future policies to be created.



> [!Resources]
> - [Microsoft: Group Policies](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview)
> - [TechTarget: What is a GPO](https://www.techtarget.com/searchwindowsserver/definition/Group-Policy-Object)