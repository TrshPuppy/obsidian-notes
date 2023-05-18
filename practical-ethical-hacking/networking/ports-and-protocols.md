
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

### [DNS](/networking/protocols/DNS/DNS.md) (Domain Name System):
This protocol (port 53) allows the DNS server on a device to resolve an IP address into its associated domain name. A domain is organized into a hierarchy starting with the Root Domain, then the Top Level Domain, and then the Second Level Domain.

In order to resolve a domain name into an IP address (so devices can send data back and forth using domain names) a device will first consult its local cache to see if it already knows the associated IP. If it doesn't it will send a request to a recursive DNS server (ISPs maintain their own recursive servers).

If the domain is not in the recursive server, a request will be sent to a Root Name Server. There used to only be 13 root name servers in the world, each with their own IP address. Root servers keep track of the next level below them in the hierarchy (Top Level Domain Servers).

Each Top Level Domain server keeps track of a specific top level domain (ex: `com` from `site.com`) and all of the Second Level Domains associated with it. From there, a TLD can be queried for the Second Level Domains it umbrellas (ex: `site` from `site.com`.

### [HTTP](/networking/protocols/http.md) & [HTTPS](/networking/protocols/https.md):
HTTP (port 80) and HTTPS (port 443) are protocols which dictate how "hypermedia documents" like HTML are transmitted between devices. These protocols relate mainly to the application layer of the OSI model.

HTTP and HTTPS were developed in order to standardize how a web browser and a web server communicate. When the browser asks a server for the information it is storing related to a website address (`site.com`), it uses HTTP. When the server sends the website data it is storing to the web browser, it is also using HTTP.

The difference b/w HTTP and HTTPS is that HTTPS is encrypted.

### [SMB](/networking/protocols/SMB.md) (Server Message Block):
SMB (ports 445 and 139) is a protocol which allows devices on a network to share and access files and programs (mostly printing programs), as well as provides inter-process-communication among processes running on remote computers.

Resources shared via SMB on a network are referred to as "shares" (`$ipc`). SMB was mainly designed to allow users on remote computers to share files and print documents via shared printers on the network. SMB also allows for *file reading and writing*.

## Common UDP Ports:



>	Resources:
>	[Wikipedia: Domain Name System](https://en.wikipedia.org/wiki/Domain_Name_System)
>	[CyberSophia: What is SMB and Why is it a Security Concern?](https://cybersophia.net/articles/what-is/what-is-smb-protocol-and-why-is-it-a-security-concern/)

