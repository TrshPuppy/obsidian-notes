
# Email
First invented in the 1970s during ARPANET by Ray Tomlinson
## Formatting and Headers:
Internet Message Format (IMF) is how email messages are formatted. Email clients usually provide the option to view email headers and/or source code.
- source code: displays the HTML which makes up the content of the message
- header: shows the headers attached to the email.
- `RFC 5322` for Internet Message Format
### Headers:
#### `From`, `Subject`, `Date`, & `To`
Usually clearly visible in the email client GUI.
#### `X-Originating IP`
The IP the email was sent from
#### `Smtp.mailfrom`/ `header.from`
the domain the email was sent from 
#### `Reply-to`
The email address a reply will be sent to
		- also may be referred to as "Return-Path"
#### `Received`
*Most reliable header*: lists all of the servers/ computers which the email traveled through
		- Read from top to bottom:
			- first received line (at the top) is the device the email was destined for
#### `domainkey-signature`
#### `Message-ID`
A unique string assigned to the email by the mail system when it is first created
		- easy to spoof/ forge
#### `Content-Type`
Tells you the format of the message (HTML or plaintext, etc.)
#### `X-Spam-Status`
A spam score created by the service or mail client
#### `X-Spam-Level`
Another spam score created by the service/ client
#### `Message Body`
#### Attachments:
The source code of attachments can also be viewed which includes headers:
- May include:
	- `Content-Type`
	- `Content-Disposition`: 'attachment', etc.
	- `Content-Transfer-Encoding`: tells how the attachment is encoded (ex: Base64)
## Delivery:
Uses 3 main protocols. *Each protocol has a designated port*. For example, SMTP uses `port 25`.
### [SMTP](/networking/protocols/SMTP.md): Simple Mail Transfer Protocol
Handles sending of emails and is the *default protocol* for outgoing mail. It is more secure b/c it uses [SSL](/networking/protocols/SSL.md).
#### Ports:
- Incoming: `port 993` - Secured ([SSL](/networking/protocols/SSL.md) enabled)
- Outgoing: `port 465` - Secured (SSL)
	- `port 587` - Also used for outgoing, but is *insecure*.
### [POP3](/networking/protocols/POP3.md): Post Office Protocol
Transfers emails b/w client and mail server. Downloads all mail from the server for your inbox *onto your local computer*. The emails are then available to you when you're offline.
#### Ports:
- Incoming: `port 995` - Secured (SSL).
	- `port 110` - Insecure
- Outgoing: 
### [IMAP](/networking/protocols/IMAP.md): Internet Message Access Protocol
Same as POP3 w/ the difference that mail is synced b/w the client and the server. Additionally, emails *stay on the server*, however the email headers can be synced so you can see what emails there are. The message body can then be downloaded when you want to read them.

Allows for emails to be available on different devices (as long as the device can connect to the internet and then to the server).
#### Ports:
- Incoming:
- Outgoing: `port 465` - Secure (SSL)
	- `port 587` - Insecure
- Other: `port 25` - Outdated and *not recommended*.
![](/networking/networking-pics/email-1.png)
> TryHackMe
### Steps:
1. email is composed by `alexa@janedoe.com` addressed to `billy@johndoe.com` w/ her favorite email client
2. the SMTP server needs to determine where to send the email
	- queries the [DNS](/networking/DNS/DNS.md) for info on `johndoe.com`
3. the DNS server obtains the info on `johndoe.com` and sends it back to the SMTP server
4. the SMTP server sends the email from Alexa across the interned to Billy's inbox at `johndoe.com`
	- has to pass through [firewalls](/cybersecurity/defense/firewalls.md)
5. The email passes through multiple SMTP servers 
6. it finally makes it to the destination server
7. Alexa's email is forwarded and sits in the local POP3/ IMAP server 
8. when Billy logs into his email client, it queries the POP3/IMAP server for new emails in his inbox
9. Alexa's email is copied (IMAP) or downloaded (POP3) to Billy's email client.
## Security:
> [!See]
> - [phishing defense](/cybersecurity/defense/phishing-defense.md)
> - [SSL](/networking/protocols/SSL.md)
### Using BCC (Blind Carbon Copy)
Protects the privacy of email addresses form the original email (recipients unable to see email addresses listed in the BCC field)

> [!Resources]
> - [Dream Host: Email Client Ports...](https://help.dreamhost.com/hc/en-us/articles/215612887-Email-client-protocols-and-port-numbers)
> - [Data Tracker: RFC 5322](https://datatracker.ietf.org/doc/html/rfc5322)
> - [Media Temple: Email Headers](https://mediatemple.net/community/products/all/204643950/understanding-an-email-header)
> - [TryHackMe](https://tryhackme.com/hacktivities?page=1&free=all&order=most-popular&difficulty=all&type=all&searchTxt=email)

