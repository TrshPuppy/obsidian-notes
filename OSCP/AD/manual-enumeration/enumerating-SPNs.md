---
aliases:
  - SPN
  - SPNs
  - Service Principle Name
  - Service Principle Names
---
# Enumerating SPNs
When a service or application in the [Windows](../../../computers/windows/README.md) operating system is launched by a user, the services's application context is defined by the user's account. When services or apps are executed *by the operating system* they are run in the *context of a [_Service Account_](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/service-accounts-on-premises)* 
## Service Accounts
Applications running on Windows can run within a set of *predefined* service accounts. These are service accounts provided by default:
### [_LocalSystem_](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
This account has extensive privileges *on the local computer* and acts as the computer on the network. The tokens included with it are: 
- `NT AUTHORITY\SYSTEM` 
- `BUILTIN\Administrators`
On all locales, it can be referred to as  `.\LocalSystem`, `LocalSystem`, or `ComputerName\LocalSystem`. This account *does not have a password*. Any services run w/i the context of `LocalSystem` inherits *the security context of the SCM* (Service Control Manager). 
#### Privileges
This account has the following privileges:
- **SE_ASSIGNPRIMARYTOKEN_NAME** (disabled)
- **SE_AUDIT_NAME** (enabled)
- **SE_BACKUP_NAME** (disabled)
- **SE_CHANGE_NOTIFY_NAME** (enabled)
- **SE_CREATE_GLOBAL_NAME** (enabled)
- **SE_CREATE_PAGEFILE_NAME** (enabled)
- **SE_CREATE_PERMANENT_NAME** (enabled)
- **SE_CREATE_TOKEN_NAME** (disabled)
- **SE_DEBUG_NAME** (enabled)
- **SE_IMPERSONATE_NAME** (enabled)
- **SE_INC_BASE_PRIORITY_NAME** (enabled)
- **SE_INCREASE_QUOTA_NAME** (disabled)
- **SE_LOAD_DRIVER_NAME** (disabled)
- **SE_LOCK_MEMORY_NAME** (enabled)
- **SE_MANAGE_VOLUME_NAME** (disabled)
- **SE_PROF_SINGLE_PROCESS_NAME** (enabled)
- **SE_RESTORE_NAME** (disabled)
- **SE_SECURITY_NAME** (disabled)
- **SE_SHUTDOWN_NAME** (disabled)
- **SE_SYSTEM_ENVIRONMENT_NAME** (disabled)
- **SE_SYSTEMTIME_NAME** (disabled)
- **SE_TAKE_OWNERSHIP_NAME** (disabled)
- **SE_TCB_NAME** (enabled)
- **SE_UNDOCK_NAME** (disabled)
### [_LocalService_](https://learn.microsoft.com/en-us/windows/win32/services/localservice-account)
Compared w/ `LocalSystem`, this account has *limited privileges* on the local computer and is primarily used by the SCM. Tokens related to it include:
- `NT AUTHORITY\LocalService`
#### Privileges
This account has the following privileges:
- **SE_ASSIGNPRIMARYTOKEN_NAME** (disabled)
- **SE_AUDIT_NAME** (disabled)
- **SE_CHANGE_NOTIFY_NAME** (enabled)
- **SE_CREATE_GLOBAL_NAME** (enabled)
- **SE_IMPERSONATE_NAME** (enabled)
- **SE_INCREASE_QUOTA_NAME** (disabled)
- **SE_SHUTDOWN_NAME** (disabled)
- **SE_UNDOCK_NAME** (disabled)
- Any privileges assigned to users and authenticated users
### [_NetworkService_](https://learn.microsoft.com/en-us/windows/win32/services/networkservice-account)
- 

SPNs ([_Service Principal Name_](https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names)) are unique ident



> [!Resources]
> - [_Service Accounts_](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/service-accounts-on-premises)
> - [_LocalSystem_](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
> - [_LocalService_](https://learn.microsoft.com/en-us/windows/win32/services/localservice-account)
> - [_NetworkService_](https://learn.microsoft.com/en-us/windows/win32/services/networkservice-account)