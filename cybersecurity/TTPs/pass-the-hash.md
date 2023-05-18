
# Pass the Hash Attack
An attack which takes advantage of [NTLM](/networking/protocols/NTLM.md) to get access to hashed passwords of user accounts. If an attacker is able to find a user name and match it with a password hash, then those pieces can be used to authenticate with #NTLM *w/o having to know the actual password*.

## Attack Vectors:
### How the hash is captured:
Obtaining a username is easy b/c it is passed *in plaintext* through the network.

Obtaining the password hash is also easy because they can usually be found in a file on the end-user system such as:
```
C:\Windows\System32\config\SAM
``` 
 which can be read by any user w/ admin privileges. Password hashes are also cached in memory and can be extracted w/ tools like #Mimikatz.

For the password hashes of #domain-controllers are normally stored in:
```
C:\Windows\ntds\ntds.dit
```
The hashes are vulnerable to #DC-Sync attacks where the domain controller (DC) is tricked into synchronizing its own password hash w/ someone impersonating another DC.

#### Other ways:
- [Responder](/cybersecurity/tools/responder.md) CLI utility
- Can be stored in memory of a [RDP Connection](/networking/protocols/RDP.md)

>[!Links]
>[Redlings](https://www.redlings.com/en/guide/ntlm-windows-new-technology-lan-manager)

 