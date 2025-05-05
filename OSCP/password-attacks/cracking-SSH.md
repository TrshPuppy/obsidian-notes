
# Cracking SSH Key Passphrases
Some [SSH](../../networking/protocols/SSH.md) private keys are *protected by a passphrase*, meaning if we compromise a user's private key, if we try to log in to their system via SSH, we will be prompted to enter their passphrase.  Unless we know the passphrase, the service won't authenticate us. 
## `ssh2john`
Fortunately, [John the Ripper](../../cybersecurity/TTPs/cracking/tools/john.md) (JtR) has an ssh passphrase cracking mode called `ssh2john`. [ssh2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/ssh2john.py) is a python script that turns an ssh private key into a hash. Don't fucking ask me how this is supposed to work, nobody seems to know. But basically, crack the passphrase on the ssh private key, you hash the private key using this tool, then give it to john, along with a wordlist like so:
```bash
┌─[25-04-26 15:17:47]:(root@192.168.144.132)-[/home/trshpuppy/oscp/password-attakcs]
└─# python3 ssh2john.py test_2_rsa > test_2_rsa.hash

┌─[25-04-26 15:17:59]:(root@192.168.144.132)-[/home/trshpuppy/oscp/password-attakcs]
└─# john --wordlist=test_wordlist test_2_rsa.hash --verbosity=6
initUnicode(UNICODE, UTF-8/ISO-8859-1)
UTF-8 -> UTF-8 -> UTF-8
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 24 for all loaded hashes
Will run 4 OpenMP threads
Loaded 14 hashes with 14 different salts to test db from test vectors
SSH OMP autotune using real db with KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES] of 2

OMP scale 1: 32 crypts (1x32) in 1.238 s, 25 c/s +
Autotune found best speed at OMP scale of 1
Press 'q' or Ctrl-C to abort, almost any other key for status
tiddies          (test_2_rsa).                               # <--- PASSWORD
1g 0:00:00:00 DONE (2025-04-26 15:18) 1.449g/s 7.246p/s 7.246c/s 7.246C/s Welcome123!..tiddies
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
Somehow,  john uses the hashed private key and a wordlist of possible pass phrases to *brute force* the passphrase from the *hashed* private key.

HOW?? you might be asking? FUCK IF I KNOW! I keep trying to find answers for this, but have not found one. SO whatever, it's magic. FML.
## Using John's `--rules`
Let's say you pwn some fools and compromise a private ssh key file. You exfiltrate it onto your machine, then try to login to the victim's SSH service, but it asks you for a passphrase. You don't know their passphrase, but let's say you know their organization's *password policy* (which they'll sometimes give you for a pen-test so you can avoid locking users out during [password spraying](../../cybersecurity/TTPs/recon/password-spraying.md)).

Yippee! With their password policy, you should know their password complexity requirements, like:
- has to be at least 10 characters
- upper case, lower case letters
- numbers
- symbols
Well, that's a lot of rules to work off. And you can use john's `--rules` flag to let john know to limit its brute force attempts to passwords which fit these requirements.
### Rulesets
You can give john a ruleset through the `--rules` flag when you run John. It tells john what variations and combinations etc to try for each word in the wordlist you give it for cracking. The ruleset needs to be added to `/etc/john/john.conf` and given a name to call at runtime.
```john.conf
[List.Rules:sshRules]
:
c A3"wow" $!
c $! Az"wow"
```
The above `sshRules` ruleset will do the following for each word in the wordlist:
- `:`: try the word as it is without changing it
- `c A3"wow" $!`: *capitalize* (`c`), insert the string `wow` at the third character in the word, and append `!` to the end
- `c $! Az"wow"`: capitalize the word, append `!` to it, then append `wow` to the end (`z`) of it
If our wordlist had two words in it (`tiddies`, `boobs`), then this ruleset would cause john to try the following passwords against the hash:
```bash
# First word in the wordlist: "tiddies"
tiddies
Tidwowdies!
Tiddies!wow

# Second word in the wordlist: "boobs"
boobs
Boowowbs!
Boobs!wow
```
There are a bunch of other rad word manipulations you can do with JtR rulesets. You can read more about them [here](https://miloserdov.org/?p=5477#54) and [here](https://www.openwall.com/john/doc/RULES.shtml)

> [!Resources]
> - [ssh2john](https://github.com/openwall/john/blob/bleeding-jumbo/run/ssh2john.py)
> - [Openwall: JtR Rules Syntax](https://www.openwall.com/john/doc/RULES.shtml)
> - [Miloser Dov: JtR Rulesets](https://miloserdov.org/?p=5477#54)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.