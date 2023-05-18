
# Windows New Technology LAN Manager
A suite of protocols from Microsoft used to authenticate users and make their activity confidential. It uses a #challenge-response mechanism where the client has to prove to the serve that it knows the password associated w/ a username *w/o passing the password over the network*.

## Challenge-Response Mechanism:
![](/networking/networking-pics/NTLM-1.png)
-[Redlings](https://www.redlings.com/en/guide/ntlm-windows-new-technology-lan-manager)

### Three messages:
#### Negotiation:
Client machine sends request to a server with the username and other configuration information.

#### Challenge:
The server responds by sending the client a randomly generated number.

#### Authenticate:
To prove that it knows the password, the client encrypts the random number using the #DES algorithm and #NT-hash of the user password as a key.

The server then verifies the users identity by making sure that the *challenge* was created w/ the correct username and password. 
- It will either use the stored NT-hash from its own #database or it will forward the challenge/response pair to the #domain-controller for validation.

## Security:
NTLM is vulnerable to a few different attack vectors:
### ![Pass the Hash](pass-the-hash.md)
### Brute Force Attack:
NTLM is vulnerable to #brute-force attacks b/c the hashing algorithm ( #DES) does not use a #salt.
- A salt adds random characters to a password before it's hashed, making it more difficult to de-obfuscate.
	-  Salting example:
		1. xxxxxxxxx (password)
		2. sha256([salt]password[pepper])

B/c there is no salting of the hashed passwords an attacker can use a [rainbow table](rainbow-table.md) to brute force the hash using pre-calculated hashes of standard passwords.
- This method is less effective on passwords which are more complex and longer (> 15 characters).

### NTLM Relay Attack
Since the user's client has no way or verifying the identity of the server, so an attack can perform a #man-in-the-middle by pretending to be the server to the client, and the client to the server.
![](/networking/networking-pics/NTLM-2.png)
-[Redlings](https://www.redlings.com/en/guide/ntlm-windows-new-technology-lan-manager)

### Other Vulnerabilities:
#### NTLM *does not support MFA*:
Multi-factor authentication ( #MFA)  would be a strong defense against NTLM attacks since adding a second authentication step would make it harder for an attacker to authenticate w/ just the password hash. Unfortunately, NTLM doesn't support MFA.

#### Letter casing:
During the hashing of a password, all lower case letters are converted to uppercase, so the #time-complexity associated w/ cracking the hash is limited. It only takes 2.5 hours to crack an 8-character password (see links).

#### The challenge:
The challenge is only a 16-byte random number which is actually not that random (NTLMv1).

#### Uses #MD4:
Not NTLMv1 and NTLMv2 use the MD4 hashing algorithm which is *considered obsolete*.

>[!Links]
>[Redlings NTLM Authentication](https://www.redlings.com/en/guide/ntlm-windows-new-technology-lan-manager) 

