# Gathering Breached Credentials
When large companies are hacked and their customer data is stolen, it's usually sold (usually on the dark web) amongst malicious actors. 

It's useful to have access to these large data dumps because the usernames/ passwords/ emails which make them up can be used to exploit targets in ethical hacking as well.
## Methodology
Gather credentials connected to a target and create a collection of interwoven info which you can use to craft an exploit against them. 

For example, finding a hashed password and using it in subsequent searches can give you additional results and connections to the target.
## [Breach Parse](../../../cybersecurity/TTPs/recon/tools/credential-harvesting/breach-parse.md)
A [tool](https://github.com/hmaverickadams/breach-parse) written by Heath Adams which can search through large collections of breached data.
### Usage:
```bash
./breach-parse.sh @tesla.com tesla.txt
```
In this example, breach-parse will scan through `tesla.txt` and find all the usernames/ emails which include "tesla.com". Then it will return all the passwords associated with those accounts. 

The results are returned in 3 files:
- `tesla-master.txt`
- `tesla-passwords.txt`
- `tesla-users.txt`
## [Dehashed](https://dehashed.com)
Dehashed is a website which (for a monthly payment) hosts breached credentials which you can search through.

Allows you to search using email, username, IP address, name, address, phone number, domain, even VIN. Dehashed will give you hashed and unhashed passwords of accounts which have been part of breaches.

All of the info you gather from dehashed can be used to build a 'dossier' on the target and individuals associated w/ it.
## Other Resources
[Hashes.org](https://hashes.org): Can be used to break a hash or find passwords which have already been broken via that hash.

> [!Resources]
> - [Heath Adams: Breach Parse](https://github.com/hmaverickadams/breach-parse)
> - [Dehashed](https://dehashed.com)
> - [Hashes.org](https://hashes.org)
