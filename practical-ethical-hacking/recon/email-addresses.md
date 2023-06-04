
# Discovering Email Addresses:

## Email Enumeration:
Email enumeration is a technique in which email addresses connected to a specific domain can be guessed by *brute forcing* an email website's login page.

The validity of an email address can be established by reading the response from the server when one attempts to login with the test email. The server may respond differently depending on if the email exists or does not exist (regardless of whether the password was correct).

Both the login page and a website's "forgot password" page can be vulnerable to this type or snooping.

### Server Response:
The server's response to the tested emails can either be scraped from the HTML of the page, or the HTTP response from the server.

Whether or not the address is valid can also be inferred from how long it takes the server to respond. With benchmarks of how long a valid address takes vs an invalid one, you can use the speed of response to guess whether the email is legit or not.

### Some *Expert* Advice:
Is email enumeration OSINT?
>	"OSINT... is typically about exploiting publicly published content, whereas there are legal questions that arise when you brute force a mailserver.
>	
>	One *could* theoretically call brute forcing a target server to be abuse of a mail server...and potentially a crime.
>	
>	This is a matter of legal interpretation. This is where you want clearly defined rules of engagement reviewed by an attorney with respect to the jurisdiction(s) involved AND the EULA for the mail server operator.
>	
>	Even scraping web servers too aggressively can create legal issues in some cases."

### Some *More Expert Advice*:
>	"That's a good question! So anything that technically doesn't "touch" the target is considered Passive Information Gathering, so I'd say falls under the category of OSINT. Harvester uses a lot of external resources to try and enumerate emails that might belong to an organization, so it'd fall under that category
>	
>	OSINT used to be a bit more passive, but I think has evolved to include both a passive and active component nowadays, so like Passive OSINT vs Active OSINT
>	
>	When I was first getting into the industry, we called it Passive Information Gathering vs. Active Information Gathering. name seems to have evolved over time
>	
>	I don't really consider brute forcing a server to be OSINT really. That's definitely a direct attack at that point to enumerate valid users, especially if you're targeting their Office365, Gmail, or even on-premise portals."

## Tools:
### [The Harvester](http://www.edge-security.com/theharvester.php)
### [ClearBit](https://chrome.google.com/webstore/detail/clearbit-connect-free-ver/pmnhcgfcafcnkbengdcanjablaabjplo)
### [Hunter.io](https://hunter.io/email-finder)

> [!Resources:]
> - [Hackers Arise: OSINT Scraping w/ theHarvester](https://www.hackers-arise.com/post/osint-scraping-email-addresses-with-theharvester)
> - [Rapid7: About User Enumeration](https://www.rapid7.com/blog/post/2017/06/15/about-user-enumeration/)

