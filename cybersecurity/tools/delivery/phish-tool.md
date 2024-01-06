
# PhishTool
Reverse engineers phishing emails.

>https://www.phishtool.com/

## Use:
Upload a suspected phishing email to the tool and it will break down:
- pertinent info (sender, recipient, timestamp, originating IP, #reverse-DNS-lookup)
- #SMTP relays and Received header (path email took to destination)
- Can toggle b/w #HTML / source code and rendered HTML of [[email]] body
- URLs and attachments
	- Hashes of attached files (with [[cybersecurity/tools/reverse-engineering/Virus-Total]] connection) 
		- free API key available to connect Virus Total

==Uploads can be flagged by the analyst as malicious and 'resolved'==
