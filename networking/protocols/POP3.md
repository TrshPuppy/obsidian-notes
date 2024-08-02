# Post Office Protocol
An [email](../email.md) protocol which is responsible for transferring emails b/w a *mail server and client.* It is not used in the actual sending of emails but in *the retrieval* of emails (from the server) to a client. 
## Process:
Emails are downloaded and stored on a *single device*.  Sent messages are stored *on the device from which they were sent*, and emails can only be accessed from the device they were sent/ downloaded to.

If you want them *to be kept on the server* `keep email on the server` option has to be selected, otherwise the messages are deleted from the server once they're downloaded.
## Security
With POP3 you can use the `STARTTLS` extension *to encrypt messages* using [SSL](SSL.md).

> [!Resources]
> - [Professor Messer](https://www.youtube.com/watch?v=yuXK_Jyosus&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=101)
> - Probably [TryHackMe](https://tryhackme.com/path/outline/presecurity)