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

When the first party (party A) wants to encrypt data and send it to the second party (party B), party A uses party B's *public key* to encrypt the data. Then party B uses *their private key* to decrypt the data. This *prevents the sensitive keys (private keys) from having to be transferred* between parties. Each party's public key (in this case, party B's) are made public because *they can only be used for encrypting*. Public keys are incapable of decrypting data. [RSA](../../computers/concepts/cryptography/RSA.md) is a common asymmetric algorithm. 
## Hashing
With hashing, the data that is inputed into the algorithm (to be hashed into a *"hash digest"*) can be of variable length, but will result in a *fixed length hexadecimal value*. For example, if you hash the sentence "I love sesame balls" and the entire work of War and Peace, they will both result in unique hashes which are the same length. 

Because of this, hashing is used for *fingerprinting* or uniquely identifying data, rather than obscuring it (like with encryption). The same piece of data when run through the same hashing algorithm *will always produce the same hash value* which is (statistically) unique (there are rare instances of *hash collision* where two separate pieces of data result in the same hash). 
### Cryptographic Hash Functions
Cryptographic hash algorithms are held to a high standard of security and are used in security-related processes. Cryptographic functions are *resistant to collision*, and can be used to *verify* the authenticity of the original input (because the output can be verified by using the same input). Additionally, some cryptographic functions can be used to prove that *data has not been tampered with*.
### Non-Cryptographic Hash Functions
Non-cryptographic hashing is useful because it can *preserve the order of data* in the original input, and because they are *less resource intensive* than cryptographic ones.
