INIT
# Lightweight Directory Access Protocol
Protocol for reading and writing *directories* over an IP ([network layer](../OSI/3-network/network-layer.md)) network. Sort of like an organized set of records *like a phone directory*. Originally, the standard specification for having a *centralized directory* on a network was written by the International Telecommunications Union and was called *DAP*. DAP ran on the [OSI-model](../../PNPT/PEH/networking/OSI-model.md) protocol stack, but LDAP is "lightweight" and runs using [TCP/IP](TCP.md).
## Uses
LDAP is used on multiple different [operating systems](../../computers/concepts/operating-system.md) including [Windows](../../computers/windows/README.md) and Apple. In Windows, it's used w/ [Active Directory](../../computers/windows/active-directory/active-directory.md). With Apple, it's used with *OpenDirectory*. There is also an implementation called *OpenLDAP*, etc..
## Security
There are more secure implementations of LDAP including LDAPS and SASL.
### LDAPS
"LDAP Secure": uses [SSL](SSL.md) to provide security.
### SASL
"Simple Authentication & Security Layer": Uses a few different ways to provide *authentication*, for example [kerberos](kerberos.md) & client certificate.

> [!Resources]
> - [Professor Messer](https://www.youtube.com/watch?v=yuXK_Jyosus&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=101)

> [!Related]
> - ports `389`, `636`
> - [kerberos](kerberos.md)
> - [Active Directory](../../computers/windows/active-directory/active-directory.md)
> - [LDAP ADSI](../../OSCP/AD/manual-enumeration/net.md#LDAP%20ADSI) 

rwxrob yt vid