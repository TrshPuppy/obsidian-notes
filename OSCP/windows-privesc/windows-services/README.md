---
aliases:
  - Windows Services
  - Windows Service
---

# Windows Services Overview
A [_Windows Service_](https://docs.microsoft.com/en-us/dotnet/framework/windows-services/introduction-to-windows-service-applications) is a background executable which is long-running and managed by the [_Service Control Manager_](https://docs.microsoft.com/en-us/windows/win32/services/service-control-manager). Windows Services are similar to daemons on [Linux](../../../computers/linux/README.md) systems. You can use [powershell](../../../coding/languages/powershell.md), Services "snap-in", or `sc.exe` (command line tool) to manage them.
## Service Control Manager
The [_Service Control Manager_](https://docs.microsoft.com/en-us/windows/win32/services/service-control-manager) is essentially a database of all the installed *services and drivers* on a Windows device. Opening the database requires *admin privileges* which grants a user account the `SC_MANAGER_ALL_ACCESS` access right.
## Running Services
[Windows](../../../computers/windows/README.md) uses three different account types to run its own services:
- `LocalSystem`: accounts which have the [SID](../security-mechanisms/SID.md)s of `NTAuthority\SYSTEM` and `BUILTIN\Administrators` in their [access-tokens](../security-mechanisms/access-tokens.md)
- `Network Services`
- `Local Service` user accounts
## Creating Services
Users or programs who want to create a Windows Service can use any of the accounts listed above, a domain user account, or a local user account to create them.

> [!Resources]
> - [_Windows Service_](https://docs.microsoft.com/en-us/dotnet/framework/windows-services/introduction-to-windows-service-applications)
> - [_Service Control Manager_](https://docs.microsoft.com/en-us/windows/win32/services/service-control-manager)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.