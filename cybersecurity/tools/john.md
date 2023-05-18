
# John the Ripper CLI Utility
A password cracking tool for encrypted and hashed passwords. Can *autodetect encryption algorithms*. #JtR performs dictionary-attacks using a #wordlist like RockYou.txt.

John also comes with  its own wordlists with thousands of common passwords.

## Mechanism:
By default John will:
- recognize the hash type of the current hashed password
- generate hashes for passwords in the wordlist
- stop when the generated hash matches the current hash

## Usage:
### Modes:
John has three modes for cracking passwords:

#### Single Crack Mode:
John takes a string and generates variations of the string to generate passwords. Give john a username and the `format` to specify the hash type and john will generate hashes based on both.
```shell
echo 'username:hashespassword' > crack.txt

$ john --single --format=raw-sha1 crack.txt

```

#### Dictionary Mode:
Provide john with a wordlist to use.
```shell
$john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha1 crack.txt
```

#### Incremental Mode:
The most powerful mode in john; tries all possible character combinations as passwords. This can *take a long time* especially if password is long and has a mix of letters, numbers, and symbols.
```shell
$ john -i:digits password.txt
```

`-i`: tells john to use incremental mode. 
`digits`: placeholder which can be used to set the *max number of characters*(?). Can also set the `--format` flag.

### Contexts:
#### Windows:
In Windows, hashed passwords are stored in the #SAM-database. SAM uses [LM/NTLM](/networking/protocols/NTLM.md) hashing format. After retrieving a password from the SAM database (see [Responder](/cybersecurity/tools/responder.md)) use this command in john:
```shell
$ john --format=lm crack.txt
```
(where `crack.txt` contains the password hash)

This command will use john's default wordlist if another wordlist isn't specified.

#### Linux:
In Linux there are two folders which store info r/t password and hashes:

##### /etc/passwd
Stores information including the username, user id, login shell, etc.

##### /etc/shadow
Stores password hashes, password expirations, etc.

One utility which comes with john is `unshadow` which combines combines the `/etc/passwd` and `etc/shadow` into one file. John can then use that combined file to crack passwords:
```shell
# using unshadow to place both files into output.db:
$ unshadow /etc/passwd /etc/shadow > output.db

# running john on the new file:
$ john --wordlist=/usr/share/wordlists/rockyou.txt output.db
```

#### Zip File Passwords:
John has another utility called `zip2john` which helps to get hashes from zipped files.
```shell
$ zip2john file.zip > zip.hashes
```
This command gets the hash form the zip file and saves it in the `zip.hashes` file. Then run `$ john zip.hashes`



>[!Links]
>[freeCodeCamp: Crack Passwords Using John the Ripper](https://www.freecodecamp.org/news/crack-passwords-using-john-the-ripper-pentesting-tutorial/)
>[erev0s: Cracking /etc/shadow with John](https://erev0s.com/blog/cracking-etcshadow-john/)

