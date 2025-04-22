
# Simple Mail Transfer Protocol
Standard protocol for communication via [email](/networking/email.md). It uses [TCP](TCP.md) to facilitate sending information b/w an email client and email server. Specifically, SMTP is a *mail delivery protocol* and not a mail *retrieval* protocol. This means SMTP will deliver an email to a mail provider's server *but not to the recipient*. Other protocols (like [POP3](POP3.md) and [IMAP](IMAP.md)) handle transferring an email from the server to the recipient.
## Technical Details
### Commands
SMTP has pre-defined text instructions which tell a client and/or server *what to do* and how to handle data (usually in the context of the client telling the server how to receive its data). 
#### `HELO/EHLO` command
These commands start the SMTP connection b/w the client and server. `HELO` is the basic version, and `EHLO` is *a specialized version of the command for a specific type of SMTP*.
##### `EHLO`
> The EHLO command operates and can be used in the same way as the HELO command. However, it additionally requests that the returned reply should identify specific SMTP service extensions that are supported by the SMTP server.
>
> If a server does not support SMTP service extensions, the client receives a negative reply to its EHLO command. When this occurs, the client should either supply a HELO command, if the mail being delivered can be processed without the use of SMTP service extensions, or it should end the current mail transaction.
> -[IBM](https://www.ibm.com/docs/en/zvm/7.3?topic=commands-ehlo)

You can also give `EHLO/HELO` a value, like `HELO x`. It's meant to be your domain, but usually the server doesn't actually care *and may even disclose its internal name* (if you give `HELO all`):
```bash
220 somedomain.com Microsoft ESMTP MAIL Service, Version: Y.Y.Y.Y ready at  Wed, 15 Sep 2021 12:13:28 +0200
EHLO all
250-somedomain.com Hello [x.x.x.x]
250-TURN
250-SIZE 52428800
250-ETRN
250-PIPELINING
250-DSN
250-ENHANCEDSTATUSCODES
250-8bitmime
250-BINARYMIME
250-CHUNKING
250-VRFY
250 OK
MAIL FROM: me
250 2.1.0 me@PRODSERV01.somedomain.com....Sender OK
```
#### Logging in/ `AUTH`
There are a few ways to authenticate w/ an SMTP server. The `AUTH` command is an *ESMTP command* meaning it is an SMTP extension. It sends the user's username and password to an email server and can be combined with the keywords:
- `PLAIN`
- `LOGIN`
- `CRAM-MD5`
- `DIGEST-MD5`
Each use a different mechanism for encoding/ [encrypting](../../computers/concepts/cryptography/symmetric-encryption.md) the credentials sent on the wire. 
##### `AUTH LOGIN`
```bash
S: 220 smtp.server.com Simple Mail Transfer Service Ready  
C: EHLO client.example.com  
S: 250-smtp.server.com Hello client.example.com  
S: 250-SIZE 1000000  
S: 250 AUTH LOGIN PLAIN CRAM-MD5  
C: AUTH LOGIN
S: 334 VXNlcm5hbWU6  
C: dGVzdEBzdXBlcm1hZ2ljb3JnLmNvbQ==
S: 334 UGFzc3dvcmQ6
C: dGVzdA==
S: 235 2.7.0 Authentication successful
```
When the client asks for `AUTH LOGIN`, the server responds w/ `334 VXNlcm5hbWU6` (base64 for "Username"). The client then needs to send the username *Base64 encoded*:
```bash
# With username 'test@supermagicorg.com' the string encoded would be:
dGVzdEBzdXBlcm1hZ2ljb3JnLmNvbQ==
# With password 'test' the string encoded would be
dGVzdA==

# The login sequence on the SMTP server:
C: AUTH LOGIN
S: 334 VXNlcm5hbWU6  
C: dGVzdEBzdXBlcm1hZ2ljb3JnLmNvbQ==
S: 334 UGFzc3dvcmQ6
C: dGVzdA==
S: 235 2.7.0 Authentication successful
```
> [!Note]
> Make sure you don't use `echo` and pipe to `base64` without giving the `-n` flag, *otherwise echo will append a new line character to your input and fuck up the results!* (new line character at end: `o=` vs without: `==`)
#### `MAIL FROM` command
Tells the server who is sending the email. 
```
MAIL FROM:<alice@example.com>
```
Sometimes a server will *auto complete* the sending address when you use `MAIL FROM`:
```bash
...
250 OK
MAIL FROM: me
250 2.1.0 me@PRODSERV01.somedomain.com....Sender OK
```
#### `RCPT TO` command
This command lists the email's recipients. Clients can send it multiple times for multiple recipients.
```
RCPT TO:<bob@example.com>
```
#### `DATA` command
This commands precedes the *content of the email* which includes the date, from, subject, to, and actual message body.
```bash
MAIL FROM:<test@tiddies.com>
250 OK
RCPT TO:<test@supermagicorg.com>
250 OK
DATA
354 OK, send.
Date: Tue, 22 April 2025 12:00:00 -0700
From: TitsMcGee <test@tiddies.com>
Subject: This is a test
To: test@supermagicorg.com

Hi,
This is a cool test.
/TMG
.
250 Queued (113.109 seconds)
```
#### `RSET` command
Resets the connection and removes any *previously transferred information* **without closing the connection**. Usually used when the client sends *incorrect information*. 
#### `QUIT` command
Ends the connection, lol.
#### `VRFY`
`VRFY` requests the server to *verify an email address*. Also see my [OSCP notes on `VRFY`](../../OSCP/enum-and-info-gathering/active/SMTP-enum.md#`VRFY`)
![`VRFY`](../../OSCP/enum-and-info-gathering/active/SMTP-enum.md#`VRFY`)
#### `EXPN`
`EXPN` can be used to ask the server for the entire list of emails which *belong to a mailing list*, or just the email of a single person (see my [OSCP notes on `EXPN`](../../OSCP/enum-and-info-gathering/active/SMTP-enum.md#`EXPN`)).
![`EXPN`](../../OSCP/enum-and-info-gathering/active/SMTP-enum.md#`EXPN`)
### Connection Opened
Since SMTP is a TCP connection, a session starts w/ the *three way handshake*. Once the connection is established b/w the client and server, the *client* begins the sending process with a `HELO`/ `EHLO` ('Hello') command.
### Email data transferred
The client sends a bunch of commands, then the email data. In addition to the email and its content, the client sends the *email header*
## SMTP Status Codes
SMTP-response-codes are updates sent by an SMTP server regarding the status of the email in its delivery process.
- Sent in response to commands sent by the SMTP-client
- Numerical codes regarding the status or an error r/t transmission of the message.
	- allows for troubleshooting errors.
![](/networking/networking-pics/SMTP-1.png)
-[mailersend](https://www.mailersend.com/blog/smtp-codes)
### Common Codes and meanings
#### 214: "Help message"
response to the `HELP` command, usually includes a link/ URL to the FAQ page
#### 220: "SMTP Service Ready"
Receiving server is ready for the next command.
#### 221: "Service closing transmission channel"
The receiving server is closing the SMTP connection.
#### 235: "2.7.0 Authentication succeeded"
The sending server's authentication is successful.
#### 250: "Requested mail action okay, completed"
The mail was successfully delivered.
#### 251: "User not local; will forward to `<forward-path>`"
The receiving server doesn't recognize the recipient but it will forward it to another email address.
#### 252: "Cannot VRFY user, but will accept message and attempt delivery"
Receiving server doesn't recognize the recipient but will try to deliver the message anyway.
#### 334: "Response to email authentication AUTH command when the authentication method is accepted"
Authentication successful.
#### 354: "Start mail input"
The email header has been received, the server is now waiting for the body of the email
## Abuse by Adversaries
> [!Try Hack Me]
> [Task 8: SMTP and C&C Communication](https://tryhackme.com/room/phishingemails4gkxh)

### Per the [MITRE-ATT&CK](../../cybersecurity/resources/MITRE-ATT&CK.md)
- Technique-1071 > [sub-technique 3](https://attack.mitre.org/techniques/T1071/003/): Adversaries can use [application-layer](/networking/OSI/application-layer.md) protocols w/ email delivery to avoid detection/ network filtering by blending in w/ existing traffic.
	- Commands to the remote #C2 will be embedded in protocol traffic between the client and server.
	- SMTP, [POP3](POP3.md) and [IMAP](IMAP.md) are very common mail protocols in network environments.
		- Include many fields and headers where data can be concealed
		- data can also be concealed in the message body
### Mitigation
Network intrusion detection and prevention systems which use signatures to identify traffic from *specific malware*.
### Detection
Monitor network traffic patterns
- Use [TLS](TLS.md) inspection for encrypted traffic which doesn't follow expected protocols/ standards and traffic flow
- Watch for correlation b/w process monitoring and traffic patterns

> [!Resources]
> - [Wireshark](https://www.wireshark.org/docs/dfref/s/smtp.html)  
> - [IMF](https://www.wireshark.org/docs/dfref/i/imf.html)
> - [SMTP codes](https://www.mailersend.com/blog/smtp-codes)
> - [IBM](https://www.ibm.com/docs/en/zvm/7.3?topic=commands-ehlo)
> - [Cloudflare](https://www.cloudflare.com/learning/email-security/what-is-smtp/#:~:text=The%20Simple%20Mail%20Transfer%20Protocol%20(SMTP)%20is%20a%20technical%20standard,their%20underlying%20hardware%20or%20software)*
> - [IBM: SMTP Commands](https://www.ibm.com/docs/en/zos/2.2.0?topic=commands-smtp)
> - [HackTricks: Pentesting SMTP](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-smtp/index.html)
> - [Sam Login: SMTP Auth Command](https://www.samlogic.net/articles/smtp-commands-reference-auth.htm)

>[!Related]
> [RFC-5321](https://datatracker.ietf.org/doc/html/rfc5321#section-2.3.7)
> `port 25`