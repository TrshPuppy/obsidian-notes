
# Windows New Technology LAN Manager
A suite of protocols from Microsoft used to authenticate users and make their activity confidential. It uses a *challenge-response* mechanism where the client has to prove to the server that it knows the password associated w/ a username *w/o passing the password over the network*.
## Challenge-Response Mechanism
NTLM incorporates two hashed password values. Both are stored on the server, and because *neither are salted*, they are used as equivalent values for the actual password. In other words, if you capture the hash from the server, you can use it to authenticate *without actually knowing the password value*. 
![](/networking/networking-pics/NTLM-1.png)
> [Redlings](https://www.redlings.com/en/guide/ntlm-windows-new-technology-lan-manager)
### Two Hashes
The two hashes are the *LM Hash* and the *NT Hash*. The LM  hash is a *DES-based* hash where DES is applied to the first *14 characters* of the password. The NT hash is an *MD4* hash of the *little-endian UTF-16 Unicode* version of the password. Both hashes are 16 bytes/ 128 bits each.
### Three messages
#### Negotiation
Client machine sends request to a server with the username and other configuration information.
#### Challenge
The server responds by sending the client a randomly generated number.
#### Authenticate
To prove that it knows the password, the client encrypts the random number using the DES algorithm and the NT-hash of the user password as a key.

The server then verifies the user's identity by making sure that the *challenge* was created w/ the correct username and password. 
- It will either use the stored NT-hash from its own database or it will forward the challenge/response pair to the domain-controller for validation.
## Security
NTLM is vulnerable to a few different attack vectors:
![My notes on Pass the Hash](cybersecurity/TTPs/exploitation/pass-the-hash.md)
### Brute Force Attack
NTLM is vulnerable to brute-force attacks b/c the hashing algorithm (DES) does not use a salt.

A salt adds random characters to a password before it's hashed, making it more difficult to de-obfuscate.
#### Salting example
1. xxxxxxxxx (password)
2. sha256([salt]password[pepper])

B/c there is no salting of the hashed passwords an attacker can use a [rainbow table](/cybersecurity/TTPs/exploitation/rainbow-table.md) to brute force the hash using pre-calculated hashes of standard passwords. This method is *less effective* on passwords which are more complex and longer (> 15 characters).
### NTLM Relay Attack
Since the user's client has no way or verifying the identity of the server, an attacker can perform a [Man in the Middle (MITM)](/cybersecurity/TTPs/exploitation/MITM.md) by pretending to be the server to the client, and the client to the server.
![](/networking/networking-pics/NTLM-2.png)
> [Redlings](https://www.redlings.com/en/guide/ntlm-windows-new-technology-lan-manager)
### Other Vulnerabilities
#### NTLM *does not support MFA*
Multi-factor authentication (MFA) would be a strong defense against NTLM attacks since adding a second authentication step would make it harder for an attacker to authenticate w/ just the password hash. Unfortunately, NTLM doesn't support MFA.
#### Letter casing
During the hashing of a password, all lower case letters are converted to uppercase, so the time-complexity associated w/ cracking the hash is limited. It only takes 2.5 hours to crack an 8-character password (see links).
#### The challenge
The challenge is only a 16-byte random number which is actually not that random (NTLMv1).
#### Uses MD4
Not NTLMv1 and NTLMv2 use the MD4 hashing algorithm which is *considered obsolete*.

>[!Resources]
> - [Redlings NTLM Authentication](https://www.redlings.com/en/guide/ntlm-windows-new-technology-lan-manager) 

> [!Related]
> - [Cracking NTLM Hashes](../../OSCP/password-attacks/cracking-NTLM.md)