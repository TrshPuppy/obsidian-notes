---
aliases:
  - encryption
---
# Intro to Encryption, Hashing & Cracking
Encryption and [hashing](../../computers/concepts/cryptography/hashing.md) are both processes which take data as input, and use various algorithms to transform the data into an output. In encryption, the process is "two-way" meaning the output can be converted back to its original input. Hashing, on the other hand, is "one-way" meaning the output after hashing *cannot be converted back to its original input* value.
## Encryption
Encryption is a *two-way* process in which a function takes an input and changes it via a mathematical equation into an output. It's two-way because the output can be *decrypted* back to its original value using a key. When data is encrypted, it's called *ciphertext*. When it's decrypted, it's called *cleartext*. There are two major types of encryption, [symmetric](../../computers/concepts/cryptography/symmetric-encryption.md) and [asymmetric](../../computers/concepts/cryptography/asymmetric-encryption.md). 
### Symmetric Encryption
In symmetric encryption, the algorithm which encrypts the cleartext into ciphertext uses the *same key value* to decrypt the ciphertext back to cleartext. When one party encrypts the data and sends it to a second party, the second party *needs the same key* to decrypt it.

If the key is exchanged via an insecure channel *then it can be intercepted and used* by an attacker, making it less secure than asymmetric encryption. One example of a symmetric algorithm is [AES](../../computers/concepts/cryptography/AES.md) (Advanced Encryption Standard). 
### Asymmetric Encryption
With asymmetric encryption algorithms, there are at least *two keys* which are distinct from each other. In other words only one key can encrypt the data, and only one key can decrypt it. The implementation is also more complicated. For two parties sharing a piece of encrypted data, both parties get two keys: a public key and a private key.

When the first party (party A) wants to encrypt data and send it to the second party (party B), party A uses party B's *public key* to encrypt the data. Then party B uses *their private key* to decrypt the data. This *prevents the sensitive keys (private keys) from having to be transferred* between parties. Each party's public key (in this case, party B's) are made public because *they can only be used for encrypting*. Public keys are incapable of decrypting data. [RSA](../../computers/concepts/cryptography/rsa.md) is a common asymmetric algorithm. 
## Hashing
With hashing, the data that is inputed into the algorithm (to be hashed into a *"hash digest"*) can be of variable length, but will result in a *fixed length hexadecimal value*. For example, if you hash the sentence "I love sesame balls" and the entire work of War and Peace, they will both result in unique hashes which are the same length. 

Because of this, hashing is used for *fingerprinting* or uniquely identifying data, rather than obscuring it (like with encryption). The same piece of data when run through the same hashing algorithm *will always produce the same hash value* which is (statistically) unique (there are rare instances of *hash collision* where two separate pieces of data result in the same hash). 
### Cryptographic Hash Functions
Cryptographic hash algorithms are held to a high standard of security and are used in security-related processes. Cryptographic functions are *resistant to collision*, and can be used to *verify* the authenticity of the original input (because the output can be verified by using the same input). Additionally, some cryptographic functions can be used to prove that *data has not been tampered with*.
### Non-Cryptographic Hash Functions
Non-cryptographic hashing is useful because it can *preserve the order of data* in the original input, and because they are *less resource intensive* than cryptographic ones.
## Applications in  Pen-testing
When you come across encrypted data, like an encrypted password, you can try to determine the key that was used to encrypt it in order to decrypt it for yourself. On the other hand, when you come across hashed data like a hashed password, the only way to crack it is to run a ton of password variations through the same hashing algorithm *until you produce the same hash*. 
### Password Cracking
Both variations of cracking encrypted passwords and hashed passwords are collectively known as [password-cracking](../../cybersecurity/TTPs/exploitation/cracking/password-cracking.md). Password cracking is usually performed *on a dedicated system* because it takes a lot of hardware resources and because you want to keep some kind of database of the passwords and hashes you've cracked over time.

Additionally, password cracking can be done *offline* so it's not vulnerable to traditional defensive techniques. It won't be detected on a network, and won't cause user account lockouts, etc.. This is unlike other password attacks where you typically are trying to [brute-force](../../cybersecurity/TTPs/cracking/brute-force.md) your way into an account or network service.

There are several tools which automate password cracking (thank god), including [John the Ripper](../../cybersecurity/TTPs/cracking/tools/john.md) and [HashCat](../../cybersecurity/TTPs/cracking/tools/hashcat.md). John is more *[CPU](../../computers/concepts/CPU.md) intensive* whereas Hashcat uses more [GPU](../../computers/concepts/GPU.md) based processing (but can also use the CPU). In general a *GPU is much faster* since modern GPUs are designed with *more cores*. However, some hashing algorithms work better on CPUs.
### Time to Crack (Hashes)
Before using a tool, its a good idea to figure out how long cracking your hashed password is going to take. To calculate the cracking time, you have to divide the *keyspace* by the *hash rate*.
#### Keyspace
[Keyspace](https://www.hypr.com/security-encyclopedia/key-space) is a *set* of all the possible valid distinct keys in a cipher or algorithm ("cryptosystem"). For example, in a simple shift algorithm like ROT13, the keyspace is limited to 13 (the number of shifts in the alphabet being used). The security of an algorithm is *proportional to the size of its keyspace*, because a smaller keyspace means less iterations an attacker has to go through to find the decryption key.

But in hashing, the keyspace is calculated by *multiplying the character set by the power of the character length of the original input*. For example, if you hash the password "tiddies123" then the keyspace is:
- the character set is 8 (there are 8 unique characters is `tiddies123`)
- the length of the input in characters is 10
$$keyspace = 8^{10} = 1,073,741,824$$
If we were actually cracking the hash for `tiddies123`, then we wouldn't know the character set, and would have to assume it's at least 26 (the number of characters in the alphabet). **BUT** then that number increases if we think the victim uses uppercase letters (+26 for all alphabetic characters in uppercase), and numbers (+10), as well as punctuation...
  
Assuming the password could include upper and lower case letters as well as numbers (ignore punctuation for a second), then our new keyspace is 
$$keyspace = (26+26+10)^{10} = 62^{10} = 8.3929e10$$
#### Hash Rate
The hash rate is *how many hashing calculations can be performed per second*. This is going to be dependent on our tool and hardware. We can use Hashcat's *benchmarking mode* to determine the hash rate for different hashing algorithms. For that we give the `-b` flag:
```bash
hashcat -b
hashcat (v6.2.5) starting in benchmark mode
...
* Device #1: pthread-Intel(R) Core(TM) i9-10885H CPU @ 2.40GHz, 1545/3154 MB (512 MB allocatable), 4MCU

Benchmark relevant options:
===========================
* --optimized-kernel-enable

-------------------
* Hash-Mode 0 (MD5)
-------------------

Speed.#1.........:   450.8 MH/s (2.19ms) @ Accel:256 Loops:1024 Thr:1 Vec:8

----------------------
* Hash-Mode 100 (SHA1)
----------------------

Speed.#1.........:   298.3 MH/s (3.22ms) @ Accel:256 Loops:1024 Thr:1 Vec:8

---------------------------
* Hash-Mode 1400 (SHA2-256)
---------------------------

Speed.#1.........:   134.2 MH/s (7.63ms) @ Accel:256 Loops:1024 Thr:1 Vec:8
...
```
Hashcat will benchmark for all of the supported hashing algorithms it cracks. The values are in `MH/s` where `1 MH/s` equals 1 millinon hashes per second. 
#### Equation
Now that we have the hash rate and the keyspace (we'll stick with a keyspace of $8^{10}$ ) we can use [python](../../coding/languages/python/python.md) to calculate the time it will take to crack `tiddies123` if its hashed using SHA2-256:
$$ cracking time = {8^{10}}/134200000 $$
```bash
python3 -c "print((8**10)/134200000)" 
8.001056810730253
```


> [!Resources]
> - [Hypr: Key Space](https://www.hypr.com/security-encyclopedia/key-space)