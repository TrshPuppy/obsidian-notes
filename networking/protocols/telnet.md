
# Telnet
A server/client application protocol.
- provides access to virtual terminals of remote systems on #local-area-networks on the internet
- Components:
	1. the protocol itself which specifies how two parties communicate
	2. the software application which provides the service
- Connection between parties made w/ [TCP](/networking/protocols/TCP.md) 

## Security:
- #telnet transfers all information in plaintext (including usernames/passwords)

## Origin:
- "teletype network", "terminal network", "telecommunications network"
- 1969: Built as a remote way to manage #mainframe-computers from remote #terminals
	- enabled researchers/ students to log into a university #mainframe from any terminal within the same building (so they wouldn't have to walk)
- SSH: telnet evolved into [SSH](/networking/protocols/SSH.md) which was a more secure network protocol
	- strong authentication
	- secures encrypted data communication b/w computers over an insecure network

>[!related]
> #port-23
> #RFC-15 & #RFC-855
> [telnet-command](telnet-command.md)

>[!links]
> https://en.wikipedia.org/wiki/Telnet
> 
> https://www.lifewire.com/what-does-telnet-do-2483642





