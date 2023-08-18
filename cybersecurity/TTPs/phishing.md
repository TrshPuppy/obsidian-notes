---
aliases: [phishing, Phishing]
---
# Phishing
A type of attack using [social engineering](/cybersecurity/TTPs/social-engineering.md) as well as spoofing in order to trick somebody into clicking a malicious link or giving up access credentials.
- URL and/or something in the email usually has something off
## Tricks and Misdirection:
- #typosquating:
	- A type of #URL-hijacking which attempts to copy a well known or trusted URL by creating one with a small typo
		- ex: `www.professormesser.com` vs `www.professormessor.com`
	- #prepending:
		- attempting to create a spoofed URL by *prepending* a letter to the beginning of a legitimate URL
		- ex: `pprofessormesser.com`
- #pretexting: lying to get information
	- the attacker pretends to be a character in a situation they create
	- ex: "Hi, we're calling from Visa regarding an automated payment to your account."
- #pharming:
	- harvesting large groups of victims
	- when an attacker redirects traffic to a legit site to a malicious/ bogus site
	- #DNS-poisoning
		- so when someone tries to visit the legitimate site, the Domain name server redirects them to the malicious site.

## Other Vectors:
All variations of a #scam
1. Vishing/ #vishing:
	- Voice phishing is a type of phishing done over the phone
	- caller ID spoofing
	- fake security checks/ bank updates, etc.
- SMishing/ #smishing:
	- done over text message
	- often include a link
	- spoofing

## Recon for a Phishing attack:
Gathering information on the victim.
- Background information
- social media (Facebook, Linkedin, etc.)
- Corporate/ company website
- More #OSINT done on a victim = better ability to create a believable pretext
	- #spearfishing:
		- when a phishing attack is highly targeted and crafted in a way to seem the most legitimate to the targeted individual.
		- May include info r/t:
			- workplace
			- family/ friends
			- recent financial transactions/ where you bank
	- #whaling:
		- a spearphishing attack directed at a CEO, CFO or other high value target
		- promises the possibility of a large catch/ gain for attacker
			- victim has more access to critical resources and credentials

## Emails:
[email](/networking/email.md) phishing is very common

### Characteristics of phishing emails:
- the sender email masquerades as a trusted entity #email-spoofing
- subject line will see legitimate
	- may use keywords like "invoice"
- body/ message looks trusted
	- HTML may be poorly formatted
	- generic
- includes hyperlinks (especially #URL-shortener )
- malicious attachment

## Phishing Analysis Tools:
1. Google Messageheader:
	- "analyzes SMTP message headers which help identify the root cause of delivery delays... Can detect misconfigured servers and mail-routing problems."
> https://toolbox.googleapps.com/apps/messageheader/analyzeheader
2. Message Header Analyzer:
> https://mha.azurewebsites.net/ 
3. Mail Header
> https://mailheader.org/
4. IPinfo.io
>  https://ipinfo.io/
5. Talos Reputation Center:
> https://talosintelligence.com/reputation
- Can be used to lookup reputations of the #hash-value of a file, etc.
6. [malware-sandboxes](/cybersecurity/tools/malware-sandboxes.md) 
7. [phish-tool](/cybersecurity/tools/phish-tool.md)

## Defense:
> See: [phishing-defense](/cybersecurity/defense/phishing-defense.md)

>[!links]
> [Professor Messer Sec+](https://www.youtube.com/watch?v=0Tr8avVrzLA&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=2&ab_channel=ProfessorMesser)c 
> [Try Hack Me Phishing Module](https://tryhackme.com/module/phishing)



