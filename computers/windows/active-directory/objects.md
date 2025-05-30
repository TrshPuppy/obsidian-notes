---
aliases:
  - Active Directory objects
  - AD objects
  - objects
---
# Objects
In AD objects are entities which represent a resource like a user, computer or printer. Each object is *defined by its attributes* which are used to store information about them. For example, a user object may have attributes like:
- full name
- telephone number
- address
- etc.
Protocols like [LDAP](../../../networking/protocols/LDAP.md) use an object's attributes to *search for and identify it*. Each type of object has a set of *pre-defined attributes* which are defined by *Object Classes*.
## Object Classes
Object classes are basically *templates or blueprints for each object type*. They define the attributes that each object should have *when its created*. There are three kinds of object classes, which are arranged in the following hierarchy:
1. __Abstract class__: a *top-level* class which contains other abstract or structural classes. It defines *the basic attributes* of an object
2. __Structural class__: the main component which defines an object and *what attributes* it should have. It *always* falls under an Abstract class or another Structural class
3. __Auxiliary class__: contains *additional attributes* that other classes can *inherit* from. Usually stores attributes *other classes don't want to define* but can inherit. Auxiliaries can be *sub-classes* or Abstract or other Auxiliary classes
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

## Object Identification
### GUIDs
When an object is created, its assigned a *128-bit unique* value called a Global Unique Identifier (*GUID*). The GUID is used to *identify the object* in the network.
### SIDs & Security Principles
Security Principles are a special category of objects which *can be authenticated* by the [operating system](../../concepts/operating-system.md). Users, computers, and Groups *are all security principles*.  In addition to having a GUID, security principles are assigned *a second unique identifier* called a Security Identifier (*SID*).
### Distinguished Names
These are analogus to the *absolute path* of the object in a file system. It specified complete information *on the object's location* within the domain. The name itself includes:
- the domain name
- OUs it belongs to
- the object's name
Each object's Distinguished Name *must be unique*.
### Relative Distinguished Names
These are analogous to *relative paths* of the object in the *current directory* of a filesystem. The relative distinguished name is the part of the distinguished name *which is unique to the object*. Any two objects within the same OU *must have unique relative distinguished names* (compared to each other).
Objects can also be defined by their Distinguished name or their Relative Distinguished name.
## Types of Objects
The following are common types of Objects in an AD domain:
### User Object
Represents a user account within the domain which can be used to log in to *domain-joined* computers. User objects have a user name and password which can be used to *authenticate them* to the domain and domain services. There are two types of user accounts:
#### - Administrators
A permanent account which has higher privileges for administrative purposes.
#### - Guests
A *temporary* account with limited access to resources and limited permissions.
### Computer Object
Represents an actual server or workstation which is *domain-joined* to the domain.
### Contact Object
Contains contact information for people who *are associated with* but *not part* of the organization.
### Groups & Organizational Units
#### Group Object
A container object which contains users, computers, and other groups. Groups are usually used to *manage permissions* in AD. All of the objects within a group *will inherit the permissions assigned to the group*.
#### Organizational Unit (OU)
[_Organizational Units_](https://en.wikipedia.org/wiki/Organizational_unit_\(computing\)) (OUs) are similar to filesystem folders b/c they act as *containers* which *store objects* in a domain. OUs can contain users, groups, computers, or *shared folders*.

OUs allow admins to group resources like user accounts, computer accounts, etc. so the information can be managed *as if it was a single unit.* This allows for the application of a *"Group Policy"* to multiple computers, and to control the user access to resources. They can also be used to delegate control over resources to multiple admins.
#### Difference b/w Groups & OUs
While both object types are container-types, they differ in the following ways:
- Groups cannot contain OUs but OUs can contain both *groups and OUs*
- A group is a *security prinsicple* and has an *SID* while an OU does not
- Groups can be added to Access Control Lists (ACLs)
- Groups can be used to *assign permissions* to the objects they contain

> [!Resources]
> - [Windows AD: AD Objects, All you need to know](https://www.windows-active-directory.com/active-directory-objects-2.html)
> - [_Organizational Units_](https://en.wikipedia.org/wiki/Organizational_unit_\(computing\)) 
> - [Microsoft: Distinguished Names](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names) 