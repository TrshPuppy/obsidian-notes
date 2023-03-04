
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