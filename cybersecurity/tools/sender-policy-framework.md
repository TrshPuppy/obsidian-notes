---
aliases: [SPF, sender-policy-framework]
---
# Sender Policy Framework/ #SPF:
Used to authenticate the send of an [[email]] by verifying that the IP address of a mail server is authorized to send email from that specific domain.
- Similar to #DMARC, an #SPF-TXT record is a list of IP addresses with care permitted to send email on behalf of your #domain 
	- When a sender tries to send an email to an email receiving server for delivery, the server checks to see ==if the sending IP is on the domain's list of allowed senders==
		- If it is: a link can be established b/w the email and the domain
		- Email is protected from #email-spoofing and #phishing 
			- lets the world know which servers are allowed to send emails on your behalf
- an SPF record is a #DNS-TXT record which contains a list of #IP-addresses which are allowed to send #email on behalf of the domain.
![[Pasted image 20230216183432.png]]
-THM

## SPF record format:
> SPF syntax: https://dmarcian.com/spf-syntax-table/
- `` v=spf ip4:127.0.0.1 include:_spf.google.com -all``
	- `vspf1`: the start of the record
	- `ip4:127.0.0.1`: which IP (and version) can send mail
	- `include:_spf.google.com`: which domain can send email
	- `-all`: non-authorized emails will be rejected


## How to make an SPF Record:
```
v=spf1 ip4:40.113.200.201 ip6:2001:db8:85a3:8d3:1319:8a2e:370:7348 include:thirdpartydomain.com ~all
```
1. SPF version: (``v=spf1``)
	- should always be version 1 b/c other versions are discontinued
2. Following version tag: ALL IP ADDRESSES AUTHORIZED TO SEND EMAIL ON BEHALF OF DOMAIN
	- `ip4:40.113.200.201 ip6:2001:db8:85a3:8d3:1319:8a2e:370:7348`
3. Include statement (`include:thirdpartydomain.com`)
	- Required for any third party organizations who are allowed to send emails on behalf of the domain
4. "all" Tag:
	- indicates what policy and how strictly it should be applied when receiving server detects a server which isn't listed
	- `-all`: (fail)- non authorized emails will be rejected
		- can cause legitimate emails to be dropped
	- `~all`: (softfail)- non-authorized emails will be accepted ==but marked==
	- `+all`: ==not secure:== allows any server to send email from your domain 

## [[SPF-surveyor]]:
Diagnostic tool from [dmarcian](https://dmarcian.com) which shows a graphical SPF record
