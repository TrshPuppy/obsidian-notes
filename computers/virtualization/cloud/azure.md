
# Azure
Azure is a cloud platform (IaaS + SaaS) from Microsoft.
![](../../computers-pics/Pasted%20image%2020240705161436.png)
## Components
### Enterprise
For a business using Azure, this is the *global account*. It is a unique identity which allows access to subscriptions, tenants, and services.
### Tenant
These are instances of Azure for the Enterprise. An Enterprise can have *multiple tenants* which is common for companies which are geographically separated or have subsidiaries. Tenants are *independent* of each other, meaning having access to one tenant does not give you access to others. 

Tenants are similar to *forests in [Active Directory](../../windows/active-directory/active-directory.md)*. Just like forests, they can have trusts established b/w them (but that has to be configured).
### Subscriptions
This is how you gain access to Azure and Azure services. Businesses get a subscription for each section of the business. For example, having one subscription for web apps in production, and another for web apps in development.
### Resources


> [!Resources]
> - [Specterops: Attacking Azure](https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a)