---
aliases: [email, Email]
---
# Email
First invented in the 1970s during #ARPANET by #Ray-Tomlinson
- Email address format:
	- `<user mailbox>@<domain>`

## Delivery:
Uses 3 main protocols:
1. [[SMTP]]: Simple Mail Transfer Protocol
	- handles sending of emails
2. [[POP3]]: Post Office Protocol
	- transfers emails b/w client and #mail-server
	- downloads all mail from the server for your inbox ==onto your local computer==
		- emails are available when you're offline
1. [[IMAP]]: Internet Message Access Protocol
	- same as #POP3
		- Difference: syncs your mail client w/ the server
			- emails ==stay on the server==
			- May just sync the email headers so you can see what emails there are, then download the message body when you want to read them
			- available on different devices
				- the device just needs to be able to connect to the mail server where the emails are stored to access them.

![[Pasted image 20230212204019.png]]
-TryHackMe.com

### Steps:
1. email is composed by `alexa@janedoe.com` addressed to `billy@johndoe.com` w/ her favorite email client
2. the #SMTP server needs to determine where to send the email
	- queries the [[DNS]] for info on `johndoe.com`
3. the #DNS server obtains the info on `johndoe.com` and sends it back to the SMTP server
4. the SMTP server sends the email from Alexa across the interned to Billy's inbox at `johndoe.com`
	- has to pass through firewalls
5. The email passes through multiple SMTP servers 
6. it finally makes it to the destination server
7. Alexa's email is forwarded and sits in the local #POP3/IMAP-server 
8. when Billy logs into his email client, it queries the POP3/IMAP server for new emails in his inbox
9. Alexa's email is copied (IMAP) or downloaded (POP3) to Billy's email client.

==Each protocol has its designated port==
ex: SMTP = #port-25

## Email Client Ports:
Mail clients connect to #mail-servers using either POP3 or IMAP

- INCOMING:
	- IMAP (Secure): ==recommended==
		- #port-993: Secure Transport
			- #SSL is enabled
	- IMAP (Insecure): #port-143 
	- POP3 (Secure):
		- #port-995: SSL enabled
	- POP# (Insecure): #port-110
- OUTGOING:
	- ==SMTP is the default for outgoing email
	- #port-465: (Secure) - SSL enabled
	- #port-587: (Insecure)
- Others:
	- #port-25: SMPT ==outdated/ not recommended==

#### Securing ports with #TLS/SSL:
- login information and messages are encrypted
- mail server is authenticated using #certificates
	- #public-key which matches a #private-key on the email/ POP3/IMAP server


>[!links]
>Ports and security:
>https://help.dreamhost.com/hc/en-us/articles/215612887-Email-client-protocols-and-port-numbers
