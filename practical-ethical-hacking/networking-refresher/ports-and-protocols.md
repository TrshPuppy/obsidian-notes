
# Common [Ports](/networking/ports.md) and Protocols
There are 65,535 ports available to connect to a device on a network. Ports are controlled by software which is managed by the device's operating system.

Each port is associated w/ a specific service or process. In order to transfer data b/w ports *the communicating ports have to be configured in the same way*.

The first ~1000 ports are reserved for specific services (ex: HTTPS is always on port 443). The rest can be used/ assigned to whatever service the computer/ program decides.

## Common TCP Ports:

### [FTP](/networking/protocols/FTP.md) (File Transfer Protocol):
FTP is a TCP protocol which is assigned to port 21. By accessing a device via port 21 you can upload, download, copy, cut, paste (etc.) files which are served by that device.

### [SSH](/networking/protocols/SSH.md) (Secure Shell Protocol) & [Telnet](/networking/protocols/telnet.md)
SSH (port 22) and Telnet (port 23) are both protocols which allows a remote party to connect to a device and execute commands on it. Telnet is the older of the two and is insecure because *all communication b/w the two parties is delivered in plaintext*.

SSH was created in order to replace telnet. With SSH communication b/w two devices *is encrypted* and both parties have to *authenticate* before sending/ receiving data.

### [POP3](/networking/protocols/POP3.md), [IMAP](/networking/protocols/IMAP.md), [SMTP](/networking/protocols/SMTP.md):
These three protocols all relate to [email](/networking/email.md). While SMTP (port 25) is responsible for sending email b/w a client and a mail server, POP3 (port 110) and IMAP (port 143) are protocols which dictate how the email is handled and stored on the server.

#### POP3: 
All the mail from the server is downloaded into the inbox *on your local computer*.

#### IMAP:
Instead of the mail being downloaded to the client's device, it *stays on the server*. Only the email headers are sent to the client's inbox, and if the client decides they want the entire message body, then it can be downloaded locally from the server.