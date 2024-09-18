
# Powerzure
Init.
## Usage
Lists all available commands in both the Info Gathering and Operational modes:
```
Invoke-Powerzure -h
```
### Info Gathering
##### `Get-AzureTarget`
Uses the current signed in user and their roles, then uses that role and returns all of the role definitions and scope of the role.
##### `Get-AzureRole`
Returns all the roles present in the environment including info on users in those roles and scope. 
- `-All` will only return roles *w/ users assigned to them*
- `-Role <role>` allows you to ask for a specific role
##### `Get-AzureRunAsAccount`
Finds any RunAs accounts being used by an Automation Account by recursively going through each resource group and Automation Account.

*Note*: If you find an account, you can extract that account's certificate using `Get-AzureRunAsCertificate`.
##### `Get-AzureRunbookContent`
- `-All`
- `-OutFilePath`
### Operational


> [!Resources]
> - [Docs](https://powerzure.readthedocs.io/en/latest/Functions/help.html)
> - [GitHub](https://github.com/hausec/PowerZure)