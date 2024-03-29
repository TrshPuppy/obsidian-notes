
# Cross-Site Request Forgery
CSRF is an exploit in web applications which allows an attacker to take advantage of a victim user's trust relationship w/ the application. The victim carries out an action *unintentionally* which the attacker has manipulated them into doing.
## Requirements:
In order for a CSRF to be successful, a few things have to be present in the attack flow:
### Privileged Action
The victim user has to have some type of privilege or trust relationship w/ the application which allows them to perform actions the attacker finds relevant and useful.

The privilege the victim user has can be over their own user-controlled data (like their password) or the permissions/ data of other users. For example, an attacker might use CSRF to take advantage of the victim user *changing their password*. Changing their password would be the privileged action in this case.
### Cookie-based Sessions
The privileged action the attacker is trying to manipulate involves sending [HTTP](www/HTTP.md) requests. Most *vulnerable* applications *rely solely on session cookies* to identify the user in these requests. If there is no other method to validate the user, than an attacker can use session cookies unique to the victim to perform CSRF.
### Predictable Request Parameters
The requested action (being made to the application via HTTP) has to contain parameters which *the attacker knows or can easily guess*. An example of a parameter which is unpredictable is the user's current password.

If the current password is used to authenticate/ secure the requests to the server, than the attacker *is unable to perform CSRF* because they don't know the user's current password.
## Mechanism
### Delivery
The delivery of CSRF exploits are very similar to [Reflected XSS](/cybersecurity/TTPs/exploitation/injection/XSS.md) attacks. The most common delivery vector is an attacker placing malicious HTML into a site that they host, then coaxing victims to visit the site (by sending them the link).
#### Self-contained Delivery
However, an attacker *doesn't have to host their own site.* CSRF attacks can also be *self-contained* like as a single URL on the vulnerable site. For example, if an application allows users to change their email *using a `GET` request* (instead of `POST`) then an attacker can insert a self-contained URL onto the site page somewhere like this:
```html
<img src="https://vulnerable-website.com/email/change?email=pwned@evil-user.com">
```
## Working Through an Example
Let's say a user has the ability to change their email address for their account. On a vulnerable application the HTTP request might look like this:
```http
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Cookie: session=yvthwsztyeQkAPzeQ5gHgTvlyxHfsAfE

email=wiener@normal-user.com
```
A request like this is vulnerable to CSRF because:
- the requested action is one that an attacker can exploit (theoretically they could manipulate the request to change the email to one they control).
- The application is only using a session cookie to identify the victim user.
- The parameters are easy to guess and change.
### Exploitation
With this vulnerable change-email action in the application, an attacker can perform CSRF by creating a webpage with the following [HTML](/coding/markup/HTML.md)
```html
<html>
	<body>
		<form action="https://vulnerable-website.com/email/change" method="POST">
			<input type="hidden" name="email" value="pwned@evil-user.com"
		</form>
		<script>
			document.forms[0].submit();
		</script>
	</body>
</html>
```
Next, the attacker has to get the user to visit their webpage. If the user is logged in the browser will *automatically pull the session cookie of the user* when it visits `vulnerable-website.com` (however, this is assuming `SameSite cookies` is not being used).

The victim browser will make the request and the application will *process it normally* because the request appears to be coming from the victim. The victim's email address will then be changed to `pwned@evil-user.com`.
## Common Defenses:
Anti-CSRF mechanisms are nowadays present on both websites *and the browser itself*.
### CSRF Tokens
CSRF tokens are unique secretes *generated by the server* and shared w/ the client. If the client wants to take a privileged action (such as submitting a form), the correct CSRF token has to be supplied by them in the request.
### SameSite Cookies
SameSite cookies is a security measure *taken by browsers* which determines when a web application's *cookies originated from another website* in a request. These will prevent an attacker from triggering privileged actions from a website that is not the vulnerable website.
#### `LAX`
`LAX` SameSite restrictions are a standard enforced by Chrome since 2021. Even though it is the proposed best standard *not all browsers employ it*
### Referrer-based Validation
The HTTP `Refferer` header helps to verify that a request *originated from the application's domain*. Some applications use this to defend against CSRF but it's *not as effective* as CSRF Tokens.

> [!Resources]
> - [OWASP: CSRF](https://owasp.org/www-community/attacks/csrf)
> - [PortSwigger: CSRF](https://portswigger.net/web-security/csrf)

