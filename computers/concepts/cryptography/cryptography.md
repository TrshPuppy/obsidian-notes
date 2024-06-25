
# Cryptography
From the Greek work 'kryptos' which means 'secret'. Cryptography is used in computer security to provide:
- confidentiality (keep things secret)
- Authentication & access control
- [non repudiation](../../Fundamentals/non-repudiation.md) (you said it, can't deny it)
- and integrity (tamper proof)
## Terms
### Plaintext
An *unencrypted message*.
### Cipher
The *algorithm* used to encrypt *or decrypt* data.
### Cryptanalysis
The art of cracking encryption. Usually done by researchers who are constantly *trying to find mathematical flaws* in a cipher.
### Key
Keys are added to the *cipher* to encrypt data. 
#### key types
Some algorithms use one key, while other are able to use multiple. It's generally more secure to have a *longer key*.
#### key security
Keys can be made more secure  by *performing multiple processes on it* such as hashing a password, then [hashing](hashing.md) the hash of the password. This is called *key stretching, key lengthening*. This is more secure because if someone were to try to *brute force* the key, they would have to brute force each hash they recover.
##### Key stretching libraries
Applications which will perform *key stretching for you*.
###### Bcrypt
 One example is *BCrypt* which is an extension of the Unix crypt library. Bcrypt will generate hashes of passwords using *multiple rounds of hashing* using *[blowfish](blowfish.md)*. 
###### PBKDF2
Password Based Key Derivation: part of the [RSA](RSA.md) library.  `RFC 2898`
## Types
Cryptography has traditionally required a lot of resources including [CPU](../CPU.md) power and time. 
### Lightweight Cryptography
With the increase in IoT devices, which have limited power (both in wattage and CPU), a type of cryptography called *lightweight cryptography* has been developed. The NIST is undergoing a lot of research on lightweight cryptography and new standards are being created.
### Homomorphic Encryption (HE)
Attempts to make it easier to work with encrypted data by allowing calculations to be performed on it *while it's encrypted*. Even though the data can be used in its encrypted state it still *can't be read w/o the key*.
#### Advantages
HE allows the secure storage of data w/p the challenge of having to decrypt it for use. It also allows for things like *research* to be done on the data as well. This is especially useful when used w/ *cloud storage* of the data.

> [!Resources]
> - [Professor Messer](https://www.youtube.com/watch?v=A6HNd1EGfIc&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=91)