---
aliases:
  - john the ripper
  - John the Ripper
---

# John the Ripper
John the Ripper (JtR) is a password cracking tool for encrypted and hashed passwords. It can *autodetect encryption algorithms* and perform dictionary-attacks using a wordlist like RockYou.txt. John also comes with  its own wordlists with thousands of common passwords.
## Mechanism
By default John will:
- recognize the hash type of the current hashed password
- generate hashes for passwords in the wordlist
- stop when the generated hash matches the current hash
## Usage
### Modes
John has three modes for cracking passwords
#### Single Crack Mode
John takes a string and generates variations of the string to generate passwords. Give john a username and the `format` to specify the hash type and john will generate hashes based on both.
```shell
echo 'username:hashespassword' > crack.txt

$ john --single --format=raw-sha1 crack.txt

```
#### Dictionary Mode
Provide john with a wordlist to use.
```shell
$john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha1 crack.txt
```
#### Incremental Mode
The most powerful mode in john; tries all possible character combinations as passwords. This can *take a long time* especially if password is long and has a mix of letters, numbers, and symbols.
```shell
$ john -i:digits password.txt
```
`-i`: tells john to use incremental mode. 
`digits`: placeholder which can be used to set the *max number of characters*(?). Can also set the `--format` flag.
#### `--show`
Show the passwords cracked from the last session (?)
### Contexts
#### Windows
In Windows, hashed passwords are stored in the #SAM-database. SAM uses [LM/NTLM](/networking/protocols/NTLM.md) hashing format. After retrieving a password from the SAM database (see [Responder](../../exploitation/tools/responder.md)) use this command in john
```shell
$ john --format=lm crack.txt
```
(where `crack.txt` contains the password hash)

This command will use john's default wordlist if another wordlist isn't specified.
#### Linux
In Linux there are two folders which store info r/t password and hashes
##### /etc/passwd
Stores information including the username, user id, login shell, etc.
##### /etc/shadow
Stores password hashes, password expirations, etc.

One utility which comes with john is `unshadow` which combines combines the `/etc/passwd` and `etc/shadow` into one file. John can then use that combined file to crack passwords
```shell
# using unshadow to place both files into output.db
$ unshadow /etc/passwd /etc/shadow > output.db

# running john on the new file
$ john --wordlist=/usr/share/wordlists/rockyou.txt output.db
```
#### Zip File Passwords
John has another utility called `zip2john` which helps to get hashes from zipped files.
```shell
$ zip2john file.zip > zip.hashes
```
This command gets the hash form the zip file and saves it in the `zip.hashes` file. Then run `$ john zip.hashes`
#### Reverse SSH keys
Using `ssh2john` john can reverse [SSH](networking/protocols/SSH.md) keys/ crack password-protected keys. To do this, first *save the key to a file*. Then use
```bash
ssh2john id_rsa > ssh.hashes
```
The, just give the output file to john:
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hashes
```
## Rulesets
You can define ruleset for manipulating *words in the wordlist*. Useful for when you know what password complexity policies are in place:
![See my OSCP notes on using John's `--rules`](../../../../OSCP/password-attacks/cracking-SSH.md#Using%20John's%20`--rules`)
## Examples which. worked!
### Cracking a KeePass (`.kbdx`) File
```bash
┌──(root㉿kali)-[/home/trshpuppy/oscp/relia/exfil]
└─# keepass2john Emma-Database.kdbx > EmmaKeePasshash.txt
                                                                                                
┌──(root㉿kali)-[/home/trshpuppy/oscp/relia/exfil]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt EmmaKeePasshash.txt 
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 60000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
welcome1         (Emma-Database)     
1g 0:00:00:05 DONE (2025-07-11 12:05) 0.1680g/s 301.1p/s 301.1c/s 301.1C/s 2hot4u..divina
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```



> [!Resources]
> - [freeCodeCamp: Crack Passwords Using John the Ripper](https://www.freecodecamp.org/news/crack-passwords-using-john-the-ripper-pentesting-tutorial/)
> - [erev0s: Cracking /etc/shadow with John](https://erev0s.com/blog/cracking-etcshadow-john/)



