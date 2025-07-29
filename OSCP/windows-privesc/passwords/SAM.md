
# Discovering Passwords in SAM
Windows stores password hashes in the [SAM](../../../computers/windows/SAM.md) (Security Account Manager). The hashes are [encrypted](../../password-attacks/README.md) with a key which can be found *in a file named `SYSTEM`*. If the current user has the ability to read SAM and SYSTEM files, then you can *extract the password hashes* from it. 
## Locations
The `SAM` and `SYSTEM` files are located in the `C:\Windows\System32\config` directory. While Windows is running *the files are locked*. However, there *may be backups* in the `C:\Windows\Repair\` or `C:\Windows\System32\config\RegBack` directories. 
## Exploitation
If the files exist, then you can exfiltrate them from the target machine and then use tools to dump the hashes from them.
### `creddump` Suite
[creddump7](https://github.com/CiscoCXSecurity/creddump7) is a suite of tools which you can run against the `SAM` and `SYSTEM` files/hives to extract domain credentials. Just clone the repo, then run the following command (`pwdump` tool):
```bash
python3 creddump7/pwdump.py SYSTEM SAM
```
### Cracking with Hashcat
Once you have the hashes, you can dump them with [hashcat](../../../cybersecurity/TTPs/cracking/tools/hashcat.md):
```bash
hashcat -m 1000 --force a9fdfa038c4b75ebc76dc855dd74f0da /usr/share/wordlists/rockyou.txt
```


> [!Resources]
> [creddump7 GitHub](https://github.com/CiscoCXSecurity/creddump7)