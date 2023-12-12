
# AD Domain Controller
Domain Controllers are physical components running the Windows Server OS within an [Active Directory](computers/windows/active-directory/active-directory.md). Specifically, they're any computer in an AD domain which is running Windows Server w/ Active Directory Domain Services installed.

On the machine running Windows Server, you can make it the *Domain Controller* of your domain by *installing AD DS*. This will *give it the role of Domain Controller*.
![](/computers/computers-pics/domain-contrroller-1.png)
> Screenshot from my Windows Server VM

By default, a domain controller *stores all the information about the domain it is located in* inside a "domain directory." The DC is, in general, the source of authentication in Windows environments and is used to verify identities in AD (among other things).
![](/computers/computers-pics/domain-controller-2.png)

> [!Resources]
> - [Wikipedia: Domain Controllers](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc786438(v=ws.10))
> - [Microsoft: Domain Controller Roles](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc786438(v=ws.10))
> - [Redmond: AD Certificate Service](https://redmondmag.com/articles/2015/06/01/ad-certificate-services.aspx)