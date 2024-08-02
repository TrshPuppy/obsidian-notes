# Info Gathering w/ Burp Suite
[Burp Suite](../../../cybersecurity/TTPs/delivery/tools/burp-suite.md) is a *web proxy* which means it can intercept web traffic.
## Firefox Setup
For firefox do the following to setup Burp:
### Open Firefox
Go to menu --> settings --> general --> Network Settings (at bottom of page)
### In Network Settings
Set "Manual proxy configuration" with:
- HTTP Proxy: `127.0.0.1`
- check 'Also use this proxy for HTTPS'
### Visit `https://burp`
In a new tab visit `https://burp`. Accept both  check boxes, then hit the `CA Certificate` button.

This will download a certificate to your `~/Downloads` folder.
### Back in Firefox
Go to Privacy & Security. Scroll down to 'Certificates' and click 'view certificates'. Then click `Import` and import the cert you just downloaded from Burp