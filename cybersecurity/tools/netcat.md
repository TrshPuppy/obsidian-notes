# Netcat Command Line Utility:
A CLI tool which is able to read and write data across a network connection using [UDP](/networking/protocols/UDP.md) as well as [TCP](/networking/protocols/TCP.md).

## Usage:
Netcat can do a few things:
- Connect to a port on a target host.
- Listen to a port for any inbound connections.
- Send data across a client to a server (after a connection has been established)
- Transfer files across a network.
- Execute programs and scripts from the client onto the server and vice versa.
- Can provide #remote-shell where shell commands can be executed.
```
nc -l -p 1234
```

### Listening:
`netcat -l`: Tells netcat to listen to the port specified by the `-p` option (1234).*To listen for multiple connects* `-k` has to be specified.

### TCP Connection:
```
nc 127.0.0.1 1234
```
Creates a #TCP connection from the client machine with the IP address on the specified port (1234). *TCP is the default.*

#### UDP Connections:
To use #UDP `-u` has to be given.

### Useful Options:
#### Verbose:
```
# listening/ server terminal:
nc -vlp 1234
listening on [any] 1234 ...
connect to [127.0.0.1] from localhost [127.0.0.1] 44972

# client terminal:
nc -v 127.0.0.1 1234
localhost [127.0.0.1] 1234 (?)
open
```
This will print additional info on the connection. The `-n` option can be used for numerical IP connection but *Netcat cannot resolve a domain name to an IP address.*

#### Wait:
After transferring data, tell Netcat to wait `w` seconds before terminating the connection:
```
# listening/ server:
nc -w 20 -lp 1234

# client:
nc -w 2 127.0.0.1 1234
```
Without `-w` *the connection will not close until Netcat is closed.*

#### File Transfer:
```
# listening/ server terminal:
nc -v -w 30 -l -p 1234  >example.txt

# client terminal:
nc -v -w 2 127.0.0.1 1234 <example.txt
```
![[Screenshot20200812225450.png]]
-[Geeks for Geeks: Netcat Basic Usage](https://www.geeksforgeeks.org/netcat-basic-usage-and-overview/)

#### Execute Shell Commands:
To execute shell commands after successful connection:
```
# listening/ server terminal:
nc -lp 1234 -c /bin/sh

# client terminal:
nc 127.0.0.1 1234
echo hello
hello
```
This provides a shell to execute shell commands. *The client is executing shell commands on the server.*

>[!Links]
>[Geeks for Geeks: Netcat Basic Usage](https://www.geeksforgeeks.org/netcat-basic-usage-and-overview/)

