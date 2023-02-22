---
aliases:[LFI, local-file-include]
---
# Local File Include Vulnerability
Type of #file-inclusion-vulnerability. Takes advantage of server side #scripting-languages like JavaScript and PHP which allow web applications to read files from file systems as they execute code.

## Mechanisms:
In the code, a path to a file you want the code to open is sent to a function which returns the content of the file (usually as a string to be printed to the webpage,etc.)

### Including files to be parsed by an interpreter:
To keep website code readable it is usually split into "modules" and organized into multiple files & directories.

To use different files in the code, the *interpreter* has to be told the relevant file-path.
```
https://target.com/?module=contact.php
```
Without sufficient filtering, an attacker can exploit a local file by replacing `contact.php` with the path of a sensitive file like the system's `passwd` file (Unix).
```
https://target.com/?module=/etc/passwd
```

### Injecting code from elsewhere in the program:
An attacker can inject code from *somewhere else on the web-server* and trick the interpreter into executing it:
```
https://target.com/?module=uploads/avatar102.gif
```

### Directory Traversal:
A #directory-traversal attack can be achieved by an attacker using an #LFI which will allow them to access potentially sensitive files such as the web-server's log files, etc.

### Including files served as downloads:
Some files are automatically opened by a browser, such as PDFs. In order for the file to be *downloaded* instead of pasted in the browser window, an additional #header has to be added instructing the browser to do so:
`Content-Disposition: attachment;filename=file.pdf`
`
Adding this header to the request will cause the browser to download the files *instead of opening them*.
```
https://target.com/?download=brochure1.pdf
```
Without #sanitizing the request, an attacker could request to download files which make up the application itself, allowing them to ==read source code== and ==find other vulnerabilities== and even ==find credentials==.

## Defense:
### Safely allow users to read/ download files:
#### Save file paths in a #database:
When filepaths are saved to a database and given a unique ID, the only thing a user can see is the ID, making it more difficult to change or view the path.

#### Use a whitelist:
Add files to a whitelist and ignore every other filename and path.

#### Store file content in a database
When possible file content should be stored in a database instead of including them on the webserver.

#### Instruct server to send download headers
Instead of having the server execute files in a specific directory such as `/download`, instruct the server to automatically send download headers instead. This points the user directly to the file on the server w/o writing additional code for a download.
```
https://target.com/downloads/brochure2.pdf
```

### Things to avoid:
#### Blacklisting file names:
Maintaining a #blacklist of file names to try to prevent an attack is mostly wasted energy b/c attackers have a huge variety of names to try using #wordlists. It usually is not enough even to block commonly attacked filenames such as */etc/passwd*, *etc/hosts*, etc.

#### Don't use user input as a source for file inclusion

#### Don't remove/ blacklist character sequences
There are known bypasses for this.

#### Don't encode file paths
Encoding filepaths with #base64, etc is easily reversible.

>[!Links]
>[Invicti: What is LFI vulnerability?](https://www.invicti.com/blog/web-security/local-file-inclusion-vulnerability/)

