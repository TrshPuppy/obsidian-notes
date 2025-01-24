# DMARC
(I'm not typing this sh-t out again)
An open source standard which ties together the results of [DKIM](/cybersecurity/defense/domainkeys-identified-mail.md) and [SPF](SPF.md) through a process called "alignment".
- DKIM (a tamper-evident domain seal associated with an email)
- SPF (a published list of servers which are authorized to send [email](/networking/email.md) on behalf of a domain)
A DMARC record is a text record w/t the [DNS](../../networking/DNS/DNS.md) which indicates the domains email policy r/t checking if a SPF or DKIM has passed or failed.

DMARC records also tell servers which handle a domain's email en-route where to send XML reports (to the reporting email listed in the DMARC record).
## DMARC Record Format
A DMARC-record can be added to a domain to help with troubleshooting and configuration of SPF and DKIM.
```
V=DMARC1; p=quarantine; rua=mailto:postmaster@website.com
```
### Sections:
#### `V=DMARC1`
Required to be in all caps. The `-v` indicates it is a DMARC record. 
#### `p=quarantine`
`-p` indicates the DMARC policy in use. In this example, if a check fails, the email will be sent to the spam folder
#### `rua=mailto:postmaster@website.com`
Where aggregate posts and data should be emailed to. `rua` provides an aggregate view of all the domain's traffic. A `ruf` tag can also be added. `ruf` tags include more sensitive information including a *forensic copy of the email*.
## DMARC Alignment
DMARC-alignment is a concept which requires that the domain used for either SPF DKIM results *MUST MATCH THE DOMAIN IN THE FROM HEADER* in the email message body. An email is "aligned" if the `from` header address of the email match the domains associated with the SPF and DKIM records. Only emails which are aligned can pass DMARC. Mismatch in domains results in a DMARC-fail.

>[!Resources]
> - [dmarcian](https://dmarcian.com/what-is-a-dmarc-record/)
> - [DMARC Alignment:](https://dmarcian.com/alignment/)
