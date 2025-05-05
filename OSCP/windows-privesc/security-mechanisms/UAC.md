
# User Account Control
UAC is a system employed by [Windows](../../../computers/windows/README.md) to restrict *unauthorized privilege escalation*. It protects the [operating-system](../../../computers/concepts/operating-system.md) by running most applications and tasks *with standard user privileges*. This is the default even when the user running them *is an Administrator*. 
## Access Tokens
To enforce UAC, Windows issues *two [access-tokens](access-tokens.md)* to admin users when they log in:
1. Standard user token or "*filtered admin token*": used to perform any non-privileged operations
2. Regular Administrator token: this token is only activated when elevated privileges *are explicitly required*. When a user tries to elevate their privileges for this token a *UAC Consent prompt* needs to be confirmed
## Integrity Levels
UAC also assigns [Integrity Levels](MIC.md) to apps and processes, as well as "securable objects". Integrity levels *determine whether an app can read from or write to files, access certain APIs,* etc..

> [!Resources]
> - [Microsoft: UAC](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/)
> - [Microsoft: How UAC works](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)