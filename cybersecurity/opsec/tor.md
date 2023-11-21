
# Tor: Onion Router
Tor is a "connection oriented anonymizing communication service."
```bash
NAME
       tor - The second-generation onion router
SYNOPSIS
       tor [OPTION value]...
DESCRIPTION
   Tor is a connection-oriented anonymizing communication service. Users 
   choose a source-routed path through a set of nodes, and negotiate a
   "virtual circuit" through the network. Each node in a virtual circuit
   knows its predecessor and  successor nodes, but no other nodes.
   Traffic flowing down the circuit is unwrapped by a symmetric key at
   each node, which reveals the downstream node.

   Basically, Tor provides a distributed network of servers or relays
   ("onion routers"). Users bounce their TCP streams, including web traffic,
   ftp, ssh, etc., around the network, so that recipients, observers, 
   and even the relays themselves have difficulty tracking the source of the
   stream.

	   Note
	   By default, tor acts as a client only. To help the network by
	   providing bandwidth as a relay, change the ORPort configuration
	   option as mentioned below. Please also consult the documentation on
	   the Tor Project’s website.
```

## Quickstart:
### Install tor:
```bash
sudo apt install tor
```

### Use [systemctl](/computers/linux/linux-processes.md) to start the service:
```bash
sudo systemctl start tor.service
```

### Check status:
```bash
service status tor
tor.service - Anonymizing overlay network for TCP (multi-instance-master)
     Loaded: loaded (/lib/systemd/system/tor.service; disabled; preset: disabled)
     Active: active (exited) since Wed 2023-07-26 14:04:43 EDT; 8s ago
    Process: 1294814 ExecStart=/bin/true (code=exited, status=0/SUCCESS)
   Main PID: 1294814 (code=exited, status=0/SUCCESS)
        CPU: 2ms
```

## Configuration:
### Proxy Chains:
Tor routes your VPN connection through proxy chaining. In the [HTTP protocol](/networking/protocols/HTTP.md) proxies/ proxy servers are servers which are configured to forward [TCP](/networking/protocols/TCP.md) connections to a desired destination. The server makes the connection *on behalf of the client* to the destination.

The initial connection is done via HTTP. Then subsequent data sent b/w the server (on behalf of the client) to the destination is sent via a TCP stream.

Proxy chaining is when you ask a proxy server to proxy the connection to a *second proxy server*, which then proxies the connection to a *3rd proxy server* and so on.

You can configure your tor ProxyChains to act dynamically, strictly or randomly.

To configure the proxy chain type:
```bash
sudo vim /etc/proxychains4.conf
```

## Using Proxychains w/ Tor:
Once the list of proxies (in the chain) is added to `/etc/proxychains4.conf` you can start using tor and proxychains to "anonymously" browse the internet, etc..

### Start tor:
```bash
sudo systemctl restart tor.service
```

### Connect w/ proxychains:
To anonymize your web traffic, use the `proxychains` command + whatever web command you want to use, for example:
```bash
proxychains firefox www.google.com
```
Or nmap:
```bash
sudo proxychains nmap -A -p- 10.0.0.2
```


> [!Resources]
> - `man tor`
> - [StackOverflow: Dynamic vs Strict Proxychains](https://stackoverflow.com/questions/20584281/differences-between-proxy-and-dynamic-proxy-patterns)
> - [StackExchange: Proxy Chaining...](https://superuser.com/questions/1213774/proxy-chaining-how-does-it-exactly-work)
> - [Proxy Scrape: What is Proxy Chaining](https://proxyscrape.com/blog/proxy-chaining#what-is-a-proxy)
> - [Sleepy: Hide Your IP Address Kali Linux](https://www.youtube.com/watch?v=fZuZ81cEh_8)
> - White PAper:
> 	- [Justia Patents: Dynamic Forward Proxy Chaining](https://patents.justia.com/patent/11637812)