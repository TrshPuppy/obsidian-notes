
# Port Scanning w/ Windows
Assuming we're on a Windows host and have no internet connection, there are some local binaries we can use to scan other hosts on the same network.
## `Test-NetConnection`
`Test-NetConnection` is a function which uses [ICMP](../../../networking/protocols/ICMP.md) to *check if a target [IP address](../../../networking/OSI/3-network/IP-addresses.md) is up* and responsive. We can use the `-Port` flag to scan a specific port as well:
```powershell
> Test-NetConnection -Port 445 192.168.50.151

ComputerName     : 192.168.50.151
RemoteAddress    : 192.168.50.151
RemotePort       : 445
InterfaceAlias   : Ethernet0
SourceAddress    : 192.168.50.152
TcpTestSucceeded : True
```
The value returned in the `TcpTestSucceeded` field tells us whether the port is open (in this case it is). 
### Scripting
If we want to test more ports using `Test-NetConnection` we can embed it into a [powershell](../../../coding/languages/powershell.md) script like this:
```powershell
PS C:\Users\student> 1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
TCP port 88 is open
...
```
This script loops from 1 through 1024, and for each digit in that range, it uses `New-Object` to create a [TCP](../../../networking/protocols/TCP.md) socket, then tries to make a connection to the target host at the current port number (whatever digit in the range we're at). If there is an error, we throw it away. If the connection is successful, we print the port number to the terminal.

For a more technical breakdown of the code: we pipe each digit into the for-loop. During each loop, the current digit is assigned to the `$_` variable. We use `$_` as an argument to `.Connect` which is a method of the new TCP socket created by `New-Object`.  If the attempted connection fails, we catch that and discard it using `2>$null`. If it's successful, we print it to the terminal.

> [!Resources]
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.
