# Internet Message Access Protocol
Protocol for [email](../email.md) which is responsible for transferring email b/w a client and a mail server.
## Process
Emails are stored on the server and can be *downloaded to multiple devices*.  Sent messages are stored on the server and can be synced across multiple devices.
## Command
You can connect to an IMAP server using [telnet](telnet.md) or [netcat](../../cybersecurity/TTPs/exploitation/tools/netcat.md). Once you do, you can use the following commands:
```bash
Login
    A1 LOGIN username password
Values can be quoted to enclose spaces and special characters. A " must then be escape with a \
    A1 LOGIN "username" "password"

List Folders/Mailboxes
    A1 LIST "" *
    A1 LIST INBOX *
    A1 LIST "Archive" *

Create new Folder/Mailbox
    A1 CREATE INBOX.Archive.2012
    A1 CREATE "To Read"

Delete Folder/Mailbox
    A1 DELETE INBOX.Archive.2012
    A1 DELETE "To Read"

Rename Folder/Mailbox
    A1 RENAME "INBOX.One" "INBOX.Two"

List Subscribed Mailboxes
    A1 LSUB "" *

Status of Mailbox (There are more flags than the ones listed)
    A1 STATUS INBOX (MESSAGES UNSEEN RECENT)

Select a mailbox
    A1 SELECT INBOX

List messages
    A1 FETCH 1:* (FLAGS)
    A1 UID FETCH 1:* (FLAGS)

Retrieve Message Content
    A1 FETCH 2 body[text]
    A1 FETCH 2 all
    A1 UID FETCH 102 (UID RFC822.SIZE BODY.PEEK[])

Close Mailbox
    A1 CLOSE

Logout
    A1 LOGOUT
```
## Security
If you use *Secure IMAP*, you're basically adding [SSL](SSL.md) to the IMAP protocol to [encrypt](../../computers/concepts/cryptography/asymmetric-encryption.md) email traffic.

> [!Resources]
> - [Professor Messer](https://www.youtube.com/watch?v=yuXK_Jyosus&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=101)
> - Probably [TryHackMe](https://tryhackme.com/path/outline/presecurity)
> - [HackTricks: Pentesting IMAP](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-imap.html)

