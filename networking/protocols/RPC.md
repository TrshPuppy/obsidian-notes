
# Remote Procedure Call 
RPC is an *inter-process communication* service which allows a client and server to communicate on a network. When the client makes a procedure call using RPC it *appears to run locally* but is actually executed on a remote computer.
## The RPC Process
A "procedure call" in RPC is a request initiated by the client and sent to a *known* remote server. The request bundles the procedure with parameters supplied by the client. 

While the server executes the process, the client is *blocked* (waits for the server's response). Once the server sends its response, the client/ application can continue.

**NOTE:** Clients can make *asynchronous* calls which are non-blocking.
### Sequence of Events:
## The RPC Protocol
The RPC protocol used in remote procedure call communications allows a program to execute code *on another address space* usually within the local network.
### Rpcbind and `port 111`
`Port 111` is a well-known port commonly used by the *rpcbind service*. The rpcbind service *listens on `port 111*` and *maintains a database* of program numbers and the ports on the server where the corresponding RPC service is available.

When a program on the client wants to make a RPC, it needs to know *where* to request the procedure and send the required parameters. To get this info, it sends a request to the rpcbind service running on `port 11`1. The request includes the *program number* it wants to call.

The rpcbind service uses the program number to look up the port number of the requested service in its database. It then returns the port number to the client, which the client can use to send its RPC request.
![](networking/networking-pics/RPC-1.png)
>	[VMWare](https://www.slideserve.com/roz/network-file-systems-nfs-and-remote-procedure-calls-rpc-powerpoint-ppt-presentation)
## Security
Exposing the rpcbind port/ `port 111` can be a security issue for a few reasons.
### Information Exposure:
Having an exposed rpcbind port makes it easy for attackers to collect information about the services and programs running on the client, server and network.

An attacker can query the port to figure out what services are running, and then find exploits and vulnerabilities in those services.
### Service Enumeration:
Along with enumerating possible services/ programs running on the target, an attacker can query the rpcbind port for *specific program numbers and ports*.
### Brute Force/ DOS:
An attacker can use the port numbers gathered from the rpcbind service to flood those services or brute force them for vulnerabilities. They can also flood the rpcbind service with requests, potentially overwhelming the system.
### Exploiting RPC:
The RPC services themselves can have vulnerabilities. An attacker who knows about these vulnerabilities can exploit them more easily if the rpcbind port is exposed.
### Lack of Encryption:
Some RPC services are *not encrypted by default* meaning the communication passed b/w the client and server can be easily intercepted. 

> [!Resources]
> - [VMWare: Layer 7 Application Identity...](https://www.slideserve.com/roz/network-file-systems-nfs-and-remote-procedure-calls-rpc-powerpoint-ppt-presentation)
> - [Wikipedia: Remote Procedure Call](https://en.wikipedia.org/wiki/Remote_procedure_call)
> - [How to Use Linux: Understanding Rpcbind...](https://www.howtouselinux.com/post/understanding-rpcbind-and-rpc)
> - [HackTricks: Pentesting Portmapper](https://book.hacktricks.xyz/network-services-pentesting/pentesting-rpcbind)