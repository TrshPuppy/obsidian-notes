
# Punycode Attack:
When an attacker redirects a user to a malicious domain which appears legitimate at first glance. By converting words/ letters which cannot be written in ASCII into Unicode in the URL/ domain name.
## ASCII vs. Unicode:
Some languages like Greek, Arabic, and Hebrew are *not* supported by ASCI. ASCII is an encoding standard which uses 7 bits to code up to 127 characters (a-z, A-Z, and 0-9)

Unicode replaces ASCII b/c it can use 32 bits to code up to 2.15 billion characters. It's also able to support all languages/ emojis.
## Punycode and ASCII:
Punycode works by converting words which cannot be written in ASCII into a unicode-ascii-encoding. [DNS](/networking/DNS/DNS.md) is limited to ASCII characters. So, punycode works by including non-ASCII characters into a domain name by creating *bootstring-encoding* of Unicode.
### Bootstring Encoding:
A complex encoding process outlined in `RFC-3492`
### Homograph Attack:
Unicode characters can look the same as ASCII characters to the naked eye
- ex: ``T`` vs `τ` (Greek Tau)
### Browsers:
Most browsers use the `xn--` prefix (ASCII compatible encoding prefix) to indicate to the browser that the domain uses punycode to represent unicode characters. This is meant to defend against Homograph attacks.
- not all browsers display the punycode prefix 
- ex: 
	- punycode: `xn--80ak6aa92e.com`
	- appearance: ``apple.com``

>[!Resources]
> - [Jamf Blog: Punycode attacks](https://www.jamf.com/blog/punycode-attacks/)
> - [RFC-2392](https://www.rfc-editor.org/rfc/rfc3492)


