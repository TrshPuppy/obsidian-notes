INIT
# Active Directory Services Interface
ADSI is the *API* which can be used to access [Active Directory](active-directory.md) *programmatically*. Administrators can use ADSI to enumerate and managed resources in an AD instance, regardless of the network environment containing the resource. ADSI can be used to carry out common tasks including:
- adding new users to a domain
- managing printers
- locating resources
- etc.
## Providers
There are two providers through which ADSI can interact w/ an AD domain, the [LDAP](../../../networking/protocols/LDAP.md) provider and the WinNT provider. Both offer interfaces, methods, and classes for programmatically interacting w/ AD. 

Providers provide *the communication protocol* through which to interact with AD. 
### LDAP Provider
The LDAP provider *is the most commonly used* of the two and *offers the most functionality*. It is a more robust and comprehensive provider compared to WinNT and is the recommended provider to use.
#### LDAP ADsPath
When using the LDAP provider, an LDAP ADsPath *is required* because it provides a way to *identify and locate* [Active Directory objects](objects.md). Without the ADsPath, ADSI can't perform any operations on the object.

The LDAP ADsPath has a *specific format* it needs to be in in order to work:
```c++
LDAP://HostName[:PortNumber][/DistinguishedName]
```
Each "level" of the path corresponds to a different *LDAP namespace*:
- `HostName`: can be a computer name, IP address, or domain name
-  `PortNumber`: if no number is specified, the default port `389` is used (if not using [SSL](../../../networking/protocols/SSL.md)) or `636` (with SSL)
- `DistinguishedName`: the [Distinguished Name](../../../computers/windows/active-directory/objects.md#Distinguished%20Names) of a *specific object*

| LDAP ADsPath example                                      | Description                                                |
| --------------------------------------------------------- | ---------------------------------------------------------- |
| LDAP:                                                     | Bind to the root of the LDAP namespace.                    |
| LDAP://server01                                           | Bind to a specific server.                                 |
| LDAP://server01:390                                       | Bind to a specific server using the specified port number. |
| LDAP://CN=Jeff Smith,CN=users,DC=fabrikam,DC=com          | Bind to a specific object.                                 |
| LDAP://server01/CN=Jeff Smith,CN=users,DC=fabrikam,DC=com | Bind to a specific object through a specific server.       |
### WinNT Provider
The WinNT provider offers less as far as interfaces, methods, and classes but *is simpler to user*. It's mostly used for *backwards compatibility* and does not support more advanced features of AD.
#### WinNT ADsPath
In order to locate and perform operations on an AD object using the WinNT provider, you need to provide a *WinNT ADsPath* with the correct formatting. The ADsPath is basically just a string which *specifies the object or namespace* you want to perform operations on.

The ADsPath can be in one of the following forms:
```c++
WinNT:
WinNT://<domain name>
WinNT://<domain name>/<server>
WinNT://<domain name>/<path>
WinNT://<domain name>/<object name>
WinNT://<domain name>/<object name>,<object class>
WinNT://<server>
WinNT://<server>/<object name>
WinNT://<server>/<object name>,<object class>
```
- `WinNT://` is the prefix that indicates the use of the WinNT provider
- `<domainName>` is the name of the domain, you could also use `<serverName>` for the name of the server (has to be either a [DNS](../../../networking/DNS/DNS.md) or [NetBIOS](../../../networking/protocols/NetBIOS.md) name)
- `<objectName>` is the name of the object being referenced
- `<objectClass>` is the class name of the object, for example: `WinNT://MyServer/Jeff,user`
## Example Scripts
Imagine you need to create a lab environment with an AD domain. You have to create the domain using a computer running Windows 2000 and the domain needs to have 1000 user accounts in the Users container of the new domain. Assume you already have automated installation procedures in place for Microsoft® Windows® 2000 Advanced Server and Active Directory.
```vbscript
' Create an object that represents the rootDSE (Root Directory Service Entry) of the Active Directory
' The rootDSE is a special entry in the Active Directory that contains information about the directory
Set objRootDSE = GetObject("LDAP://rootDSE")

' Use the rootDSE object to get the default naming context of the Active Directory
' The default naming context is the top-level naming context of the directory
' Get the DN (Distinguished Name) of the "Users" container in the default naming context
Set objContainer = GetObject("LDAP://cn=Users," & _
 objRootDSE.Get("defaultNamingContext")) ' Concatenate the LDAP path with the DN of the "Users" container

' Loop 1000 times to create 1000 user objects
For i = 1 To 1000
 ' Create a new user object in the "Users" container with a CN (Common Name) of "UserNo" followed by the loop counter
 Set objLeaf = objContainer.Create("User", "cn=UserNo" & i)
 
 ' Set the sAMAccountName attribute of the new user object to "UserNo" followed by the loop counter
 ' The sAMAccountName is a required attribute for user objects in Active Directory
 objLeaf.Put "sAMAccountName", "UserNo" & i
 
 ' Commit the changes to the directory by calling the SetInfo method
 objLeaf.SetInfo
Next ' Move to the next iteration of the loop

' Display a message to the user indicating that 1000 users have been created
Wscript.Echo "1000 Users created."
```
The above is a [VBS](../../../coding/languages/VBS.md) (Visual Basic) script (from [Microsoft](https://learn.microsoft.com/en-us/previous-versions/tn-archive/ee156529(v=technet.10))) which adds *1000 user accounts* to an AD domain (don't run this, I'm not responsible for you bricking a machine).
### Accessing ADSI w/ PowerShell
![See my OSCP notes on Using ADSI w/ PowerShell](../../../OSCP/AD/manual-enumeration/LDAP-ADSI.md#Using%20ADSI%20w/%20PowerShell)

> [!Resources] 
> - (video) [NickIsATechNerd: Defining ADSI](https://www.youtube.com/watch?v=LzwyWzyPT9M)
> - [Microsoft: ADSI](https://learn.microsoft.com/en-us/windows/win32/adsi/active-directory-service-interfaces-adsi)
> - [Microsoft: ADSI Overview](https://learn.microsoft.com/en-us/previous-versions/tn-archive/ee156529(v=technet.10))
> -  [LDAP ADSI Provider](https://learn.microsoft.com/en-us/windows/win32/adsi/adsi-ldap-provider)
> - [WinNT ADSI Provider](https://learn.microsoft.com/en-us/windows/win32/adsi/winnt-adspath)

> [!Related]
> - My OSCP notes on [LDAP-ADSI](../../../OSCP/AD/manual-enumeration/LDAP-ADSI.md)