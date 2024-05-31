
# Zero Trust
Zero Trust is a security model which attempts to strengthen an organization's security standing by *assuming the user cannot be trusted*. This means that a user, their device, input, etc. is treated as non-trustworthy *even if they were previously trusted*.

Organizations attempt to implement ZTA through identity verification and validation. For example, a user and device should be verified *before being granted access*. It follows that the *least amount of privilege* should be given to those accessing resources.
## Mutual Authentication
In a zero trust architecture the identity and integrity of users and devices are checked *irrespective* of location (can include [IP address](networking/OSI/3-network/IP-addresses.md)). When a request is made to access and/or manage data, ZTA the decision to grant access to the user/device is sometimes based on *Attribute-Based Access Control* (ABAC).
### ABAC
Attribute-Based access control (also called 'policy-based') is a methodology used to determine a subject's authorization by evaluating attributes associated with that subject.

The policy rules are based on *Boolean functions* of the subject's attributes as well as the attributes of the object (they're attempting to access) and the environment.

> [!Resources]
> - [Wikipedia: Zero trust security model](https://en.wikipedia.org/wiki/Zero_trust_security_model)
> - [Wikipedia: ABAC](https://en.wikipedia.org/wiki/Attribute-based_access_control#File_server_security)