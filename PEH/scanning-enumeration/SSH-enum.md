
# Enumerating SSH
When dealing w/ [SSH](/networking/protocols/SSH.md) any login attempt is considered *exploitation.*
## Kioptrix
Because Kioptrix is outdated, the errors which return when attempting an SSH connection tell us about the target.
```bash
ssh 10.0.2.5
Unable to negotiate with 10.0.2.5 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1
```
Using the `ssh` command w/ no flags set, the target returns information to us *that it shouldn't*. This is a finding. The above error is telling us that the target did not find a match for us as a known host, and is offering to connect anyways as long as key exchange is [Diffie-Hellman](/cybersecurity/cryptography/diffie-hellman.md).

W/ this error returned from the target, we can attempt to ssh again with a `-o` flag (options) set to `KexAlgorithms=+diffie-hellman-group1-sha1` to match the key exchange method they're offering.
```bash
ssh 10.0.2.5 -o KexAlgorithms=+diffie-hellman-group1-sha1                                        
Unable to negotiate with 10.0.2.5 port 22: no matching cipher found. Their offer:...
```
Depending on how the target responds, you may be able to keep changing the `KexAlgorithms` flag to match their offer and get a connection. But connecting via SSH is *not considered enumeration*. This would be considered exploitation.
### Versioning:
In [our nmap scan](nested-repos/PNPT-study-guide/PEH/scanning-enumeration/kioptrix.md) we can see that nmap found an OpenSSH version of `2.9p2`, which we can report as information disclosure.

> [!My previous notes (linked in text)]
> - [nmap](https://github.com/TrshPuppy/obsidian-notes/tree/main/CLI-tools/linux/nmap.md) 
> - [Diffie-Hellman](https://github.com/TrshPuppy/obsidian-notes/tree/main/cybersecurity/cryptography/diffie-hellman.md)
> - [SSH](https://github.com/TrshPuppy/obsidian-notes/tree/main/networking/protocols/SSH.md)

