
# Punycode Attack:
When an attacker redirects a user to a malicious domain that appears legitimate at first glance.
- Converting words/ letters which cannot be written in #ASCII into #unicode ASCII #encoding

## ASCII vs. Unicode:
- Some languages like Greek, Arabic, and Hebrew are not supported by ASCII
	- ASCII is an encoding standard which uses 7 bits to code up to 127 characters (a-z, A-Z, and 0-9)
	- #Unicode replaces ASCII b/c it can use 32 bits to code up to 2.15 billion characters
		- supports all languages/emojis

## Punycode and ASCII:
Punycode works by converting words which cannot be written in ASCII into a #unicode-ascii-encoding.
- [DNS](/networking/routing/DNS.md) is limited to ASCII characters
- punycode works by including non-ASCII characters into a #domain-name by creating #bootstring-encoding of Unicode 
	- (complex encoding process)
	- #RFC-3492
- Unicode characters can look the same as ASCII characters to the naked eye
	- ex: ``T`` vs `τ` (Greek Tau)
	- called a #homograph-attack

### Browsers:
Most browsers use the `xn--` prefix (ASCII compatible encoding prefix) to indicate to the browser that the domain uses punycode to represent unicode characters.
- To defend against Homograph attacks
- not all browsers display the #punycode-prefix 
	- ex: 
		- punycode: `xn--80ak6aa92e.com`
		- appearance: ``apple.com``


>[!links:]
>https://www.jamf.com/blog/punycode-attacks/
>
> RFC-2392:
>https://www.rfc-editor.org/rfc/rfc3492


