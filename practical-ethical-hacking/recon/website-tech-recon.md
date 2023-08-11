
# Identifying Website Technology
Identifying the technology being used on both the frontend, and perhaps the backend of a web application is important in the recon phase because the info can be used to plan your attack.

The technologies used likely have vulnerabilities which you can exploit later.

## Tools:
### [BuiltWith](https://builtwith.com)
This is a website where you can enter the name of a website and get some basic information back about the technologies the website uses in its architecture.

### Wappalyzer:
Wappalyzer is an open source tool which you can use as an [addon](https://addons.mozilla.org/addon/wappalyzer) to your web browser or in your [command-line](https://github.com/wappalyzer/wappalyzer).

### [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
WhatWeb is another command line utility which comes with Kali Linux. It's open source and can be found on GitHub.

#### Usage:
Here is an example of the output when scanning `morningstarsecurity.com` (creators of WhatWeb):
```bash
http://morningstarsecurity.com [301 Moved Permanently] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Apache/2.4.29], IP[104.225.220.14], RedirectLocation[https://morningstarsecurity.com/], UncommonHeaders[x-redirect-by], x-pingback[http://morningstarsecurity.com/xmlrpc.php]
https://morningstarsecurity.com/ [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], Google-Analytics[Universal][UA-791888-17], HTML5, HTTPServer[Apache/2.4.29], IP[104.225.220.14], JQuery[3.6.4], Open-Graph-Protocol[website], Script[application/ld+json,text/javascript], Title[Home - MorningStar Security], WordPress, WordpressSuperCache
```

**See more on WhatWeb [here](cybersecurity/tools/scanning-enumeration/whatweb.md)

> [!Resources]
> - [BuiltWith](https://builtwith.com)
> - [Wappalyzer GitHub](https://github.com/wappalyzer/wappalyzer)
> - [Wappalyzer Addon](https://addons.mozilla.org/addon/wappalyzer)
> - [WhatWeb](https://github.com/urbanadventurer/WhatWeb)

>[!My previous notes:]
> - [WhatWeb](https://github.com/TrshPuppy/obsidian-notes/blob/main/cybersecurity/tools/recon/whatweb.md)




