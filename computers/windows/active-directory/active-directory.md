
# Active Directory
Active Directory is an *identity management service* created by Microsoft to manage Windows 'domain networks.' The information it stores about the network, its users, and services, is organized into different types of objects including 'Computers,' 'Users,' 'Printers,' etc..
## Architecture
AD is made up of *four parts:*
- **Forests:** contains domains and define a single directory w/ security boundaries.
- **Domain Name System (DNS):** handles name resolution for domain controllers and their location w/i the hierarchy
- **Schema:** provides the definitions used to create objects stored in the directory
- **Data store:** manages the storage of information  for each Domain Controller
### Domains and Forests
A forest w/i an AD is a logical/ security boundary containing multiple domains (which in turn contain their own *organizational units* or 'OU's). The point in organizing and partitioning the AD in this way is to  make replicating the stored data more efficient by not replicating it when it doesn't need to be.

![](/computers/computers-pics/active-directory-1.gif)
> [Microsoft](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759186(v=ws.10))
#### Forest
The forest is the *highest level of logical structure* in the hierarchy. It represents *a single directory* and is self-contained. Forests are 'security boundaries' b/c an *Administrator w/i a forest has complete control over all access and information* stored in that forest.

The Administrator also *has full access to the domain controller* associated with that forest.
#### Domain
Domains are used to *partition the information sored inside the directory into smaller portions* so the info is easier to replicated and control. When data stored in a directory is replicated it can be replicated to *the entire forest and between domain controllers* or just to the domain controllers *relevant to its domain.*
##### Replication topology
... is a term used to describe how replication is managed within a domain. If a domain is designed well, Administrators are able *to control how replicated data flows throughout the network.*
#### Organizational Units (OUs)
OUs allow Admins to group resources like user accounts, computer accounts, etc. so the information can be manages *as if it was a single unit.*

This allows for the application of a *"Group Policy"* to multiple computers, and to control the user access to resources. They can also be used to delegate control over resources to multiple admins.
### Domain Name Service
Active Directory uses a DNS to resolve/ locate domain controllers within the AD. In order to help clients locate domain controllers, the DNS uses:
- Locator: to locate domain controllers
- domain names: given to each domain
- DNS objects: containers which store DNS information
#### Locator
The Locator component of AD DNS contains 'locators' which are both [IP](/networking/OSI/IP-addresses.md) and [DNS](/networking/DNS/DNS.md) compatible. These locators *enable clients to locate domain controllers* w/i the AD environment.
#### Domain Names
Every domain in an AD has a DNS domain name (ex: `trshpuppy.com`). Every computer joined to a domain also has  a DNS name *which incudes the domain's name* (ex: `examplecomp.trshpuppy.com`).

Domains and computers are represented *as objects (in the AD)* and as *nodes* in the DNS.
#### DNS Objects
Data stored in an AD is stored in an *AD container object*. This object contains *2 other nested sub objects* and together they make up a *`dnsZone`* classed object. 

Each `dnsZone` object contains a `dnsNode` object for *every unique name in the zone*. Each `dnsNode` object contains a `dnsRecord` attribute which stores the value of *every resource record associated w/ that DNS name*.
![](computers/computers-pics/active-directory-2.png)
> I made this lol
### Objects & the Schema
All of the information stored in AD is stored inside objects and every object type *has a definition stored in the schema.* Each definition is made up of a *class object* and an *attribute object*. 

When creating a new definition (for an object), multiple class and attribute objects are used. There are two types of definitions stored in the schema, also called *'schema objects'*:
1. `classSchema` objects: definitions stored in the schema which are used to to define classes.
2. `attributeSchema` objects: definitions in the schema which are used to define attributes
#### `classSchema` objects
`classSchema` objects are actually used to *group attributes* logically. For example, a `user` class object could be used to store the attributes associated with that user such as their name, username, and password.

When a new user is created the directory *uses the the `user` class definition* to create the user. `classSchema` objects can also be nested to create more complex objects.
#### `attributeSchema` objects
`attributeSchema` objects are used by the directory to *make sure that data being stored is valid*.  Each attribute (used in combination to make up objects) *has its own attributes* which help define the type of data it stores. An object's `attributeSchema` is basically a record/ definition of the individual attributes which make it up.

The `attributeSchema` should include information about each attribute's:
- type of data it stores
- syntax of the data it stores
- whether or not it's required vs optional
![](computers/computers-pics/active-directory-2%201.png)
> Me
### Data Store
Every domain controller in a forest *has a data store*. Data stores are made up of several components which store and retrieve data in the directory.

On the Domain Controller the Data Store is normally stored (by default) in the `%SystemRoot%\NTDS` folder.
#### Components:
1. **Interfaces**: The interfaces for the data store are used by clients and other servers to communicate and interact with the data store. The interfaces involved include LDAP(which uses the [LDAP protocol](/networking/protocols/LDAP.md)), REPL, MAPI, and SAM.
2. **DSA** (`Ntdsa.dll`): The DSA *provides the interfaces* on each domain controller. It runs as `Ntdsa.dll`. In addition to providing the interfaces, it *enforces directory semantics*, maintains *the schema*, guarantees *object identity*, and *enforces data types on attributes*.
3. **Database layer**: This is an API in the `Ntdsa.dll` which provides an interface b/w the directory database and other applications. Its purpose is to *protect the database from direct access*. It also provides an abstracted object hierarchy for the database (which itself is flat).
4. **ESS** (`Esent.dll`): The ESE *communicates with records in the database*.  It does so using the name attribute of an object.
5. **Database files**: Directory information is stored in a single database file in the datastore. The datastore also makes use of log files where it writes temporary transactions.
## Physical Components
### Domain Controllers
See [Domain Controllers](computers/windows/active-directory/domain-controller.md).

> [!Resources]
> - [Microsoft: AD DS Overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)
> - [Microsoft: AD Structure & Storage Tech.](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759186(v=ws.10))
