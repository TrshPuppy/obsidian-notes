
# Privileged Access Management
Privileged Access Management (PAM) is access management policies for *priviliged accounts* and is instituted by organizations as part of their effort to protect their most critical infrastructure. In general, PAM gives them the ability to monitor and closely control access to privileged accounts (which can access critical and sensitive systems and/or data).
## Basic Requirements
### Identification
Identification of which accounts are privileged. Privileged accounts usually have *root or admin* level access to critical systems, devices and data.
### Access Request
In order for a user to earn privileged access to accounts, they start by requesting access through the PAM system. Requests usually go through an approval process headed by managers and specifically designated personnel.
### Authentication & Authorization
Before a user is granted access, PAM requires them to authenticate. Usually this involves *multi-factor authentication* (MFA). Once a user is authenticated, PAM grants them access *only to resources necessary for their task* and bases this off roles and responsibilities associated with the account.
### Session Mgmt
When a user accesses a priviliged account, PAM creates a 'sandboxed' session which is monitored and audited. The user is isolated from other users/ environments which prevents them from *moving laterally* through the network. Sessions also include session recordings, keystroke logging, and real-time monitoring. This creates a *detailed audit trail* of all the actions a user takes during their session.
### Password Mgmt
PAM systems usually provide password vaults/ managers which store credentials for priviliged accounts. These password managers rotate passwords automatically at configured intervals which reduces the risk of unauthorized access. Whenever a user accesses passwords in the PAM system, their access is logged and audited.
### Access Control Policies
PAM systems use access control policies to dictate who can access which privileged accounts under which conditions. Each policy is *granular*, meaning it can be tailored by an organization to meet their requirements.
### Audit and Reporting
PAM systems maintain comprehensive logs of activities related to privileged accounts. These logs are included in compliance reporting, incident response, and continuous monitoring.

> [!Resources]
> - [SentinelOne: What is PAM](https://www.sentinelone.com/cybersecurity-101/identity-security/what-is-privileged-access-management-pam/)