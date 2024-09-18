
# Secure/ Multipurpose Internet Mail Exchange
[Asymmetric encryption](../computers/concepts/cryptography/asymmetric-encryption.md) standard which applies public key encryption and *digital signatures* to mail content so [email](email.md) traffic can be encrypted and secured. Requires a PKI (public key infrastructure) or similar organization method for keys
A protocol for digitally signing and encrypting [email](/networking/email.md) which provides the following services:
## S/MIME Signatures
### Authentication Signatures 
validate the identity of the sender. It does so by providing a way to ==differentiate them from others==, thus proving their uniqueness. 
### Nonrepudiation:
Similar to a legally binding document which is signed, nonrepudiation prevents the owner of a signature from disowning it.
### Data Integrity:
Digital signatures validates to the receiver that the contents of the email were not altered in anyway en route. Any alteration which occurs en route will invalidate the signature.
## S/MIME Encryption
SMTP does not secure email content (the content can be read along any intercepted part of the emails path to receiving inbox). S/MIME encryption provides:
### Confidentiality
Protects the content of the email because only the intended recipient can view it. Before leaving the sender's inbox, the content is encrypted to a non-readable format and can only be decrypted by the intended recipient.
### Data Integrity
The algorithm which the content of the email goes through in order to be encrypted helps ensure the data's integrity. Any changing to the contents of the email ==while it is encrypted== will taint the original content and make it unreadable on the receiving side (proving it has lost integrity).

>[!Resources]
> - [Microsoft on S/MIME](https://learn.microsoft.com/en-us/exchange/security-and-compliance/smime-exo/smime-exo)
> - [Wikipedia: S/MIME](https://en.wikipedia.org/wiki/S/MIME)
> - [Professor Messer](https://www.youtube.com/watch?v=yuXK_Jyosus&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=101)

