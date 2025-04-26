---
aliases:
  - Security Account Manager
---
# Security Account Manager
The [Windows](README.md) Security Account Manager (SAM) is a [database](../../coding/databases/DBMS.md) file in Windows NT, 2000, XP, Vista, 7, 8, 9, 10, and 11 which is used for *storing user passwords*. Its used to authenticate local *and remote* users. However, starting with Windows 2000 [active directory](active-directory/active-directory.md) is used to authenticate remote users.
## Storage
User passwords are [hashed](../concepts/cryptography/hashing.md) and then stored in `%SystemRoot%/system32/config/SAM` mounted on `HKLM/SAM`. This file is a "registry hive" and `SYSTEM` *privileges are required to view it*. 
### Hashing
The passwords are hashed as an LM or [NTLM](../../networking/protocols/NTLM.md) hash.
### `SYSKEY`
Since NTLM hashes are *relatively easy to crack*, the `SYSKEY` feature was added to the SAM to prevent threat actors from cracking them offline. When `SYSKEY` is enabled, the on-disk copy of the SAM file is *partially [encrypted](../../OSCP/password-attacks/README.md)* which in turns encrypts the hashed user passwords.

The key used to encrypt the SAM file and its passwords is called the `syskey`. However, as of Windows 10, `SYSKEY` was removed because it was insecure and would be used by attackers to *lock users out of their systems* (lol Microsoft, you tried I guess).

> [!Resources]
> - [Wikipedia: Security Account Manager](https://en.wikipedia.org/wiki/Security_Account_Manager)