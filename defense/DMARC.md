---
aliases: [DMARC, domain-based-message-authentication-reporting-and-conformance]
---
# DMARC
(I'm not typing this sh-t out again)
An open source standard which ties together the results of [[domainkeys-identified-mail|DKIM]] and [[sender-policy-framework|SPF]] through a process called "alignment".
- DKIM (a tamper-evident domain seal associated with an email)
- SPF (a published list of servers which are authorized to send [[email]] on behalf of a domain)

A DMARC record is a text record w/t the #DNS which indicates the domains email policy r/t checking if a SPF or DKIM has passed or failed.

DMARC records also tell servers which handle a domain's email en route where to send #XML reports (to the reporting email listed in the DMARC record)

## DMARC Record Format:
A #DMARC-record can be added to a domain to help with troubleshooting and configuration of SPF and DKIM.
```
V=DMARC1; p=quarantine; rua=mailto:postmaster@website.com
```

- `V=DMARC1`: Required to be in all caps
	- `-v` indicates it is a DMARC record
- `p=quarantine`: `-p` indicates the DMARC policy in use
	- in this example, if a check fails, the email will be sent to the spam folder
- `rua=mailto:postmaster@website.com`: Where aggregate posts and data should be emailed to.
	- #RUA provides an aggregate view of all the domain's traffic
	- a #RUF tag can also be added
		- RUF tags include more sensitive information including a ==forensic copy of the email==
		- not required for deployment of DMARC
	- reports are written in Extensible Markup Language (XML)

## DMARC Alignment
#DMARC-alignment is a concept which requires that the domain used for either SPF DKIM results ==MUST MATCH THE DOMAIN IN THE FROM HEADER== in the email message body.
- an email is "aligned" if the #from-header address of the email match the domains associated with the SPF and DKIM records
- Only emails which are aligned can pass DMARC
- mismatch in domains results in a #DMARC-fail

>[!Links]
>dmarcian:
>https://dmarcian.com/what-is-a-dmarc-record/
>
>DMARC Alignment:
>https://dmarcian.com/alignment/
