
# The Web in Depth: HTTP Requests
(How to do bug bounties from [hackerone](https://www.hacker101.com/start-here))

# [HTTP](/networking/protocols/HTTP.md) Requests:
## Basic Format:
```HTTP
VERB/resource/locator HTTP/1.1
Header1: Value1
Header2: Value2
...
<Body of request>
```

## Types of Request Headers:
### Host:
Indicates the desired host *handling* the request.

### Accept:
Indicates which #MIME types are accepted *by the client*. Usually specifies #JSON or #XML formatting of the output for web services.

### Cookie:
Passes cookie data to the server. A #cookie is a key-value pair of data sent from the server to the client. Cookies reside w/ the client for a fixed period of time.

Every cookie has a domain pattern which it matches. Sometimes the pattern is very specific, sometimes it only matches a #root-domain and will match any subdomains associated w/ the root. 

#### Cookie Security:
Example: cookies which are added for `.example.com` can be *read by any subdomain of `example.com`.* Cookies added to a subdomain can only be ready by that subdomain and its children.

Subdomains can set cookies for its own children and parent *but not for any siblings*:
- Example: `test.example.com` can set cookies for `parent.text.example.com` and for `example.com` but not for `test2.example.com`
- *In code a cookie's scope should be limited so an attacker can't take advantage of the ability to set cookies for domains they aren't meant to set cookies for.*

#### Cookie Flags:
These flags are set in the `Set-Cookie` header which is indicated by the server.
1. `Secure`: The cookie will only be accessible to #HTTPS pages.
2. `HTTPOnly`: The cookie cannot be read by JavaScript (cookie is only sent via web requests).
	- If this isn't set, the cookie can't be ready using the `document.cookie` variable available in JS.

### Referer:
Page leading to the current request. This is *not* passed to other servers when using [HTTPS](/networking/protocols/HTTPS.md) on the origin.

### Authorization:
Used for basic authentication pages. Takes the form of: `Basic <base64'd username:password>`. Ex: [NTLM](/networking/protocols/NTLM.md).

> [!Links]
> [hacker 101: The Web in Depth](https://www.hacker101.com/sessions/web_in_depth.html)

