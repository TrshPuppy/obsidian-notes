
# Enumerating SMTP
[SMTP](../../../networking/protocols/SMTP.md) is a networking protocol used in [email](../../../networking/email.md) communication. Specifically, it is used to *deliver emails to an email server* but not to the actual recipient. SMTP servers which are present on a target network can provide a lot of interesting information because many of them support commands like `VRFY` and `EXPN` which can expose information.
## Commands
SMTP has [multiple commands](../../../networking/protocols/SMTP.md#Commands) but `VRFY` and `EXPN` can specificallly be used to *verify existing users* on the server. 
### `VRFY`
[`VRFY`](../../../networking/protocols/SMTP.md#`VRFY`) can be used to request the server to *verify a specific email address*
```bash
kali@kali:~$ nc -nv 192.168.50.8 25
(UNKNOWN) [192.168.50.8] 25 (smtp) open
220 mail ESMTP Postfix (Ubuntu)
VRFY root
252 2.0.0 root
VRFY idontexist
550 5.1.1 <idontexist>: Recipient address rejected: User unknown in local recipient table
^C
```
In this command, we're using [netcat](../../../cybersecurity/TTPs/exploitation/tools/netcat.md) to connect to an SMTP server running on the target. Once the connection is established, we're given a simple [tty](../../../computers/linux/terminal-tty-shell.md) we can use to send commands to the server. The `VRFY root` command given in the snippet above is us asking the server to verify if the user `root` exists as a recipient on the server.

The `VRFY idontextist` command triggers an error response from the server, indicating `idontexist` is not a valid recipient on the server.
### `EXPN`
[`EXPN`](../../../networking/protocols/SMTP.md#`EXPN`) can be used to ask the server is a specific mailbox exists on a server. What's useful about this command is that the server will answer *with the entire email address* of the requested user:
```bash
kali@kali:~$ nc -nv 192.168.50.8 25
(UNKNOWN) [192.168.50.8] 25 (smtp) open
220 mail ESMTP Postfix (Ubuntu)
EXPN billy
 250 billy@abc.com
^C
```
We can also use `EXPN` to verify entire mailing lists. For example, if there is a mailing list called `employees`, we can use `EXPN` to ask the server for *all of the email addresses on that mailing list*:
```bash
kali@kali:~$ nc -nv 192.168.50.8 25
(UNKNOWN) [192.168.50.8] 25 (smtp) open
220 mail ESMTP Postfix (Ubuntu)
EXPN employees
 250-carol@abc.com
 250-greg@abc.com
 250-marsha@abc.com
 250 peter@abc.com
^C
```
Notice that some of the emails in the list have a hyphen b/w `250` and the address. This means that the *response from the server continues onto the next line* (there are more items to list). That's also why `peter@abc.com` doesn't have a hyphen (his is the last email in the mailing list). 

`EXPN` can be used to find both email addresses and mailing lists. If there is an entry for the queried name, the SMTP server will return that entry (regardless if it is a single address or an entire mailing list).
## Automating Enumeration
### Python
Let's create a python script to automate using the `EXPN` command to verify a list of users. In our user list, let's also add names which are likely to be the names of mailing lists. Our [python](../../../coding/languages/python/python.md) script is going to open a TCP socket, connect to the target SMTP server, and issue the `EXPN` command for a given name:
```python
#!/usr/bin/python

import socket
import sys

if len(sys.argv) != 3:
	print("Use: smtp_enum.py <name file> <target_ip>")
	sys.exit(0)

# Create the socket:
soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to target SMTP server (port 25):
ip = sys.argv[2]
con = s.connect((ip, 25))

# Grab banner and print:
banner = s.recv(1024)
print(banner)

# Get names from file and create list:
name_file = f"{sys.argv[1]}"
names = []

with open(name_file) as nf:
	for current_name in nf:
		current_name = current_name.strip()
		names.append(current_name)

# Issue EXPN command for each user in the list:
for name in names:
	name_to_issue = name.encode()
	soc.send(b`EXPN ` + name_to_issue + b`\r\n`)

	res = soc.recv(1024)
	print(f"Result for {name}: {res})

# Close socket:
soc.close()
```
### Windows
We can use [`Test-NetConnection`](../../../CLI-tools/windows/Test-NetConnection.md) again to automate SMTP enumeration from a Windows machine as well:


> [!Resources]
> - [IBM: SMTP EXPN Command](https://www.ibm.com/docs/en/zos/2.2.0?topic=sc-expn-command-verify-whether-mailbox-exists-local-host)

