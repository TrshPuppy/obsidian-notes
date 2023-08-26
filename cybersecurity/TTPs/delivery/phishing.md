
# Phishing
A type of attack using [social engineering](cybersecurity/TTPs/delivery/social-engineering.md) as well as spoofing in order to trick somebody into clicking a malicious link or giving up access credentials.
## Tricks and Misdirection:
### Typosquatting/ [punycode](cybersecurity/TTPs/delivery/punycode.md)
A type of *URL hijacking* which attempts to copy a well known or trusted URL by creating one with a small typo.
- ex: `www.professormesser.com` vs `www.professormessor.com`
### Prepending:
Attempting to create a spoofed URL by *prepending* a letter to the beginning of a legitimate URL:
- ex: `pprofessormesser.com`
### Pretexting: 
Lying to get information; the attacker pretends to be a character in a situation they create
- ex: "Hi, we're calling from Visa regarding an automated payment to your account."
### Pharming:
Harvesting large groups of victims; when an attacker *redirects traffic* from a legit site to a malicious/ bogus site.
#### DNS Poisoning
Pharming traffic usually also involves *DNS Poisoning*; when someone tries to visit the legitimate site, the Domain name server redirects them to the malicious site.
## Other Vectors:
The following additional vectors can be thought of as *variations of scamming* the victim:
### Spearfishing:
When a phishing attack is highly targeted and crafted in a way to seem the most legitimate to the targeted individual.

May include info r/t:
- workplace
- family/ friends
- recent financial transactions/ where you bank
#### Whaling:
A spearphishing attack directed at a CEO, CFO or other high value target. Usually promises the possibility of a large catch/ gain for attacker b/c the victim has *more access to critical resources and credentials*.
### Vishing:
Vishing is a type of phishing done over the phone ('voice-phishing'). Usually includes *caller ID spoofing* in order to entice the victim to answer the call.
### SMishing
Smishing is phishing done over text messaging. Usually includes a malicious link as well as *spoofing*.
## Recon for a Phishing attack:
More [OSINT](/cybersecurity/TTPs/recon/OSINT.md) done on a victim = better ability to create a believable pretext.
### Type of Information to Gather/ Sources:
- Background information
- social media (Facebook, Linkedin, etc.)
- Corporate/ company website
## Emails:
The most common vector for phishing is via [email](/networking/email.md).
### Characteristics of phishing emails:
- the sender email masquerades as a trusted entity via email spoofing
- subject line will seem legitimate
	- may use keywords like "invoice"
- body/ message looks trusted
	- HTML may be poorly formatted
	- generic
- includes hyperlinks (especially URL shortener)
- malicious attachment
- URL and/or something in the email usually has something off

## Phishing Analysis Tools:
### [Google Messageheader](https://toolbox.googleapps.com/apps/messageheader/analyzeheader):
A tool which "analyzes SMTP message headers which help identify the root cause of delivery delays... Can detect misconfigured servers and mail-routing problems."
### [Message Header Analyzer:](https://mha.azurewebsites.net/)
### [Mail Header](https://mailheader.org/)
### [IPinfo.io](https://ipinfo.io/)
### [Talos Reputation Center:](https://talosintelligence.com/reputation)
Can be used to lookup reputations of the hash value of a file, etc.
### [Malware-sandboxes](/cybersecurity/tools/malware-sandboxes.md) 
### [phish-tool](/cybersecurity/tools/phish-tool.md)

## Defense:
> See: [phishing-defense](/cybersecurity/defense/phishing-defense.md)

> [!Resources]
> - [Professor Messer Sec+](https://www.youtube.com/watch?v=0Tr8avVrzLA&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=2&ab_channel=ProfessorMesser)
> - [Try Hack Me Phishing Module](https://tryhackme.com/module/phishing)
