---
aliases: [SMTP, simple-mail-transfer-protocol]
---
# Simple Mail Transfer Protocol
Standard protocol for communication via [[email]]. To start using SMTP, you simply provide a server name, #SMTP-port, username, and password. The #SMTP-server then sends emails on your behalf.

>[!Related]
> #RFC-5321: https://datatracker.ietf.org/doc/html/rfc5321#section-2.3.7

## SMTP Status Codes:
#SMTP-response-codes are updates sent by an SMTP server regarding the status of the email in its delivery process.
- Sent in response to commands sent by the #SMTP-client
- Numerical codes regarding the status or an error r/t transmission of the message.
	- allows for troubleshooting errors.
![[Pasted image 20230219112529.png]]
-[mailersend](https://www.mailersend.com/blog/smtp-codes)

### Common Codes and meanings:
214: "Help message"
>A response to the `HELP` command, usually includes a link/ URL to the FAQ page

220: "SMTP Service Ready"
> Receiving server is ready for the next command.

221: "Service closing transmission channel"
> The receiving server is closing the SMTP connection.

235: "2.7.0 Authentication succeeded"
> The sending server's authentication is successful.

250: "Requested mail action okay, completed"
> The mail was successfully delivered.

251: "User not local; will forward to `<forward-path>`"
> The receiving server doesn't recognize the recipient but it will forward it to another email address.

252: "Cannot VRFY user, but will accept message and attempt delivery"
> Receiving server doesn't recognize the recipient but will try to deliver the message anyway.

334: "Response to email authentication AUTH command when the authentication method is accepted"
> Authentication successful.

354: "Start mail input"
> The email header has been received, the server is now waiting for the body of the email

## Abuse by Adversaries:
> [!Try Hack Me]
> Task 8: SMTP and C&C Communication: https://tryhackme.com/room/phishingemails4gkxh

Per the #MITRE-ATTACK:
- #technique-1071> [sub-technique 3](https://attack.mitre.org/techniques/T1071/003/): Adversaries can use [[application-layer]] protocols w/ email delivery to avoid detection/ network filtering by blending in w/ existing traffic.
	- Commands to the remote #C2 will be embedded in protocol traffic between the client and server.
	- SMTP, #POP3, and #IMAP are very common mail protocols in network environments.
		- Include many fields and headers where data can be concealed
		- data can also be concealed in the message body

### Mitigation:
Network intrusion detection and prevention systems which use #signatures to identify traffic from ==specific malware==.

### Detection:
Monitor network traffic patterns:
- Use #TLS/SSL inspection for encrypted traffic which doesn't follow expected protocols/ standards and traffic flow
- Watch for correlation b/w process monitoring and traffic patterns
- 



>[!Links]
> [[Wireshark]] SMTP traffic analysis:
> SMTP: https://www.wireshark.org/docs/dfref/s/smtp.html
> IMF: https://www.wireshark.org/docs/dfref/i/imf.html
> 
> SMTP codes:
> https://www.mailersend.com/blog/smtp-codes

