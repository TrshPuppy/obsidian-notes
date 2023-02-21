
# Defense Against [[Phishing]] 
Per the [MITRE-ATT&CK]() matrix, there are two techniques for mitigating #phishing attacks:

> Playbook: https://www.incidentresponse.org/playbooks/phishing

1. Software Configuration:
	- `` 'Use anti-spoofing and email authentication mechanisms to filter messages based on validity checks of the sender domain (using SPF) and integrity of messages (using DKIM). Enabling these mechanisms within an organization (through policies such as DMARC) may enable recipients (intra-org and cross domain) to perform similar message filtering and validation.'``	
2. User training:
	- `Users can be trained to identify social engineering techniques and spearfishing attempts.`

## Domain Configuration:
#### [sender-policy-framework](/cybersecurity/defense/sender-policy-framework.md) (SPF)
- Allows a domain to only allow emails from specified IP addresses:
- Incoming email from an unlisted IP will either be:
	1. Blocked and dropped (fail)
	2. Accepted but marked as non-trusted (softfail)
	3. Accepted (no IPs specified as trusted in the SPF record)

#### [domainkeys-identified-mail](/cybersecurity/defense/domainkeys-identified-mail.md) (DKIM)
- Authenticates the origin of an email by using #RSA encryption and matching public and private key pairs.

#### Domain-based Message Authentication Reporting & Conformance ([DMARC](/cybersecurity/defense/DMARC.md))
- Emails can pass DMARC if they "Align"
- to align the address in the #from-header of the email must match the domains listed in the SPF and DKIM records

## Secure/Multipurpose Internet Mail Extensions ([SMIME](/cybersecurity/defense/SMIME.md))
Protocol for sending digitally signed and encrypted messages using #public-key-cryptography.
- Guarantees data integrity and #nonrepudiation 
- Ex: If Bob wants to send an email to Mary:
	- Bob needs a digital #certificate which contains his public key
	- Bob "signs" the sending email with his private key
	- Mary also needs a certificate.
	- When she receives Bob's email, she can decrypt it with his public key
	- When Mary replies to Bob's email, the same will happen on his end
	- Now they both have each other's certificates for future emails b/w them

>[!Links]
>Try Hack Me Room:
>https://tryhackme.com/room/phishingemails4gkxh
>
>MITRE-ATT&CK:
>https://attack.mitre.org/techniques/T1598/
>
>Domain Health Checker (checks DKIM, SPF and DMARC):
>https://dmarcian.com/domain-checker/

