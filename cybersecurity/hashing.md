
# Hashing
A #hash-value is the result of a #hashing-algorithm 
	A #hash-value is a *numeric* value of fixed length which uniquely identifies data
		- can be any type of data (file, photo, video, etc)
	- A #hash-value is *not cryptographically secure* if two values create the same hash

### Common #hashing-algorithm s:
1.  #MD5 (Message Digest)
	- defined by #RFC-1321
	- a #cryptographic has function which produces a #128-bit-hash value
	- **NOT CONSIDERED CRYPTOGRAPHICALLY SECURE**
	- updated by #RFC-6151 
		- describe multiple attackes against #MD5 hasing including #hash-collision 
2. #SHA-1 
	- definded by #RFC-3174 
		- developed by the #NSA in 1995
	- #SHA-1 takes inpput and creates a #160-bit-hash value string as a 40 digit #hexadecimal number
	- **BANNED IN and DEPRECATED 2011-2014**
		- susceptible to #brute-force attacks
3. #SHA-2 
	- developed by #NIST (national institute of standards and technology) and the #NSA in 2001
		- to replace #SHA-1 
	- Has multiple variants
		- most common = #SHA-256
			- #SHA-256 returns an output which is a #256-bit-hash as a 64 digit #hexadecimal number

>[!Tools]
> [[Cyber-Chef]]
> [[OPSWAT]] 
> [[Virus-Total]]

> [!Command Line]
> 
