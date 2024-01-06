
# Hashing
Hashing is the process of creating a hash-value by putting data through an algorithm. Every piece of data produces a unique hash (with some overlap), and the hash becomes a unique fingerprint for that data.

Any type of data can be hashed including passwords, photos, entire applications, etc.. The algorithm produces a *numeric* value of fixed length which uniquely identifies the data.

A hash is *not considered cryptographically secure* if two different pieces of data create the same hash.
## Common Hashing Algorithms:
### MD5 (Message Digest)
This algorithm is defined by RFC-1321. It's a cryptographic hash function which produces a 128-bit hash value.
- **NOT CONSIDERED CRYPTOGRAPHICALLY SECURE**
- updated by RFC-6151 
	- describes multiple attacks against MD5 hashing including hash-collision 
### SHA-1 
Algorithm defined by RFC-3174 and developed by the NSA in 1995. SHA-1 takes input and creates a 160-bit hash value string as a 40 digit *hexadecimal* number
- **BANNED and DEPRECATED 2011-2014**
	- susceptible to brute-force attacks
### SHA-2 
Developed by NIST (national institute of standards and technology) and the NSA in 2001 to replace SHA-1. This algorithm has multiple variants, the most common being *SHA-256*.
#### SHA-256
Returns an output which is a 256-bit hash as a 64 digit hexadecimal number.

> [!Tools]
> - [Cyber-Chef](cybersecurity/resources/Cyber-Chef.md)
> - [OPSWAT](cybersecurity/resources/OPSWAT.md) 
> - [Virus-Total](cybersecurity/tools/reverse-engineering/Virus-Total.md)

> [!Command Line]
> - see [checksums](/cybersecurity/opsec/checksums.md)
> - [hash-id](cybersecurity/tools/cracking/hash-id.md)


