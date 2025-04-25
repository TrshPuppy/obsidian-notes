# Post Office Protocol
An [email](../email.md) protocol which is responsible for transferring emails b/w a *mail server and client.* It is not used in the actual sending of emails but in *the retrieval* of emails (from the server) to a client. 
## Process
Emails are downloaded and stored on a *single device*.  Sent messages are stored *on the device from which they were sent*, and emails can only be accessed from the device they were sent/ downloaded to.

If you want them *to be kept on the server* `keep email on the server` option has to be selected, otherwise the messages are deleted from the server once they're downloaded.
## Commands
You can connect to a POP3 server using [telnet](telnet.md) or even [netcat](../../cybersecurity/TTPs/exploitation/tools/netcat.md). When you do, you have access to some POP3 commands:
### `USER` & `PASS`
Login with a username and password:
```bash
└─# telnet $t 110
Trying 192.168.186.199...
Connected to 192.168.186.199.
Escape character is '^]'.
+OK POP3
USER test@supermagicorg.com
+OK Send your password
PASS test
+OK Mailbox locked and ready
```
### `LIST`
List contents of the current user's mailbox:
```bash
LIST
+OK Mailbox scan listing follows
1 1823
2 1825
3 1819
.
```
### `RETR`
Retrieve a message. Follow the command with the message's number:
```bash
RETR 1
+OK 1823 octets
--- all message headers and message ---
.
```
### `TOP`
Retrieves part of a message. Not all servers support this command. Works similar to `RETR` but you specify *the number of lines you want*. All of the headers will be returned as well. If you want to get *only the headers* then the second value you give should be `0` (zero messages):
```bash
# Returning just the headers:
TOP 1 0
+OK Top of message follows
--- all message headers ---
.

# Returning the headers and first 10 lines of message body:
TOP 1 10
+OK Top of message follows
--- all message headers ---
--- first 10 lines of body ---
. 
```
## Security
With POP3 you can use the `STARTTLS` extension *to encrypt messages* using [SSL](SSL.md).

> [!Resources]
> - [Professor Messer](https://www.youtube.com/watch?v=yuXK_Jyosus&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=101)
> - Probably [TryHackMe](https://tryhackme.com/path/outline/presecurity)
> - [Electric Tool Box: POP3 Commands](https://electrictoolbox.com/pop3-commands/)