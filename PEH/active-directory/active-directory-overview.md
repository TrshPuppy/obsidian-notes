
# Overview of Active Directory
[Active Directory](computers/windows/active-directory/active-directory.md) is an identity service created by Microsoft to manage Windows 'domain networks.' The information it stores about the network, its users, and services, is organized into different types of objects including 'Computers,' 'Users,' 'Printers,' etc..

Authentications w/i AD is *done with a protocol called [kerberos](/networking/protocols/kerberos.md)* which is  a protocol that uses a ticket system and a client-server architecture.

> 'A directory is a hierarchical structure that stores information about objects on the network. A directory service, such as Active Directory Domain Services (AD DS), provides the methods for storing directory data and making this data available to network users and administrators. For example, AD DS stores information about user accounts, such as names, passwords, phone numbers, and so on, and enables other authorized users on the same network to access this information.'

-[Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)

**NOTE:** Even though AD is primarily used in Windows environments, it can also be used on other OSes such as Linux.
## Why is AD Important for Pentesting?
- It is the *most commonly used* identity management service *in the entire world*. 
- It's possible to exploit it *without using patchable exploits* (ships with vulnerabilities which are commonly from misconfiguring, etc.).
- The same credentials are used across multiple computers and services.
## Physical Components
The components which make up AD can be organized into physical and logical components.
### Domain Controllers
If AD were a phonebook, the [Domain Controller](computers/windows/active-directory/domain-controller.md) can be thought of as the entity which *hosts the phonebook.* [According to Microsoft](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc786438(v=ws.10)), a DC is a 

> 'server that is running a version of the Windows Server operating system and has Active Directory installed.'

By default a domain controller stores information *for the domain in which it is located.* However, a DC designated as a **Global Catalog Server** stores all the objects *for all the domains within the forest.*
### AD DS Data Store
The *Directory Store* (also just called the 'directory') stores all of the data of its Domain Controller (see [Active Directory: Data Stores](/computers/windows/active-directory/active-directory.md)). It contains the `Ntds.dll` or `Ntds.dit` file which contains *a lot of information including password hashes*.

On the Domain Controller the Data Store is normally stored (by default) in the `%SystemRoot%\NTDS` folder. However, it's only accessible through the process and protocols used by the Domain Controller.
## Logical Components
### AD DS Schema
> See [Active Directory: Objects & Schema](/computers/windows/active-directory/active-directory.md)

The AD stores *all of its information in objects*. Each object belongs to a class which defines the attributes which make it up. In order to keep object creation and storage consistent, both classes and attributes have to *follow their specific schema.*

Schemas provide rules for how class objects and attribute objects are made and used. They also help to enforce what objects can be created/ exist in an individual directory.
### Domain
> See [Active Directory: Domain Name Service](/computers/windows/active-directory/active-directory.md)

Domains are used to group together objects in an AD environment. The boundary of a domain acts both as an administrative boundary, an authentication boundary, and a replicative boundary.
#### Administrative boundary
The domain boundary makes it easier for Admins to apply policies and enforce access permissions to objects in the same domain.
#### Authentication boundary
The domain boundary allows for the ability to limit scope and access to resources of the objects w/i the domain.
#### Replicative boundary
When data is replicated b/w domain controllers, it flows through only the domains involved. This helps to limit its spread across the entire forest/ network.
### Tree
When there are multiple domains in AD DS, they can be arranged into a *hierarchy called a tree*. Domains within a tree:
- Share the same namespace as the parent domain
- Can have additional child domains ('subdomains')
- Have a default established trust relationship b/w peers called a 'two-way transitive trust'
### Forest
A forest is a collection of trees. The domain trees within a forest share specific things including:
- a common schema
- a common configuration partition
- " global catalog (to enable searching)
- the Enterprise Admins and Schema Admins groups

Collecting trees into a forest in AD means *trust can be established between all domains in the forest.*

**NOTE:** In an AD which includes a forest, if you're able to compromise the domain admin of a single domain, resources beyond the domain are *still protected by the Enterprise and Schema admins*. These can be compromised by various forms of privilege escalation.
### Organizational Units
These are just containers which group objects together. For example, if you have a group of computers that you want to apply the same policy to, you can group them into an OU for the purpose of applying that policy.
### Trusts
Trusts are a mechanism which users can use to *gain access to resources in a different domain.* There are two types of trusts:
1. **Directional**: The direction trust flows is from the *trusting domain* to the *trusted* domain.
2. **Transitive**: Instead of trust flowing between two domains, the trust granted to one domain is extended to other domains outside of the two-domain trust.

Within a forest *all domains trust all other domains*, so if two domains are within the same forest, they automatically grant each other trust.

> [!Resources]
> - [Microsoft: AD DS Overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)
> - [Microsoft: Domain Controllers Roles](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc786438(v=ws.10))
> - My previous notes (linked throughout the text) can all be found [here](https://github.com/trshpuppy/obsidian-notes)


