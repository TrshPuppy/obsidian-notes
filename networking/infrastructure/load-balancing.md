
# Load Balancing
A networking infrastructure implementation which takes incoming traffic from multiple devices and distributes it accross multiple servers (such as web servers). This is usually done w/o the end-user knowing. For example, some websites are supported by multiple web servers so that when a query comes in from the website (from a user), it can be sent to any one of the servers on the backend (by the load balance.
## Fault Tolerance
Load Balancing provides fault tolerance and redundancy. When one server crashes or is out of service, others are available to take its work, thereby preventing service outages to end-users.
## Configuration
![](../networking-pics/Pasted%20image%2020240710142956.png)
### TCP Offload
Load balancers are capable of [TCP](../protocols/TCP.md) offload, which means they take on the responsibility of the processing required to maintain TCP sessions with clients. Having the load balance handle this, instead of each individual server, gets rid of protocol overhead on the servers and makes TCP communication much faster. 
### [SSL](../../hidden/Sec+/25%%203%20Implementation/3.1%20Secure%20Protocols/SSL.md) Offload
Similar to TCP offload, a load balancer can be configured to be responsible for the processing of SSL traffic. This includes encrypting and decrypting communication. This makes SSL communication w/ the client much faster and efficient (and easier to manage) because it's being handled in one place instead of by each individual server.

This also means that communication *between the load balancer and the other servers is in cleartext*, which introduces possible security risk.
### Caching
Load balancers which provide caching *keep a copy of common responses* in cache. This allows them to respond to common queries using their cache instead of having to forward the query to a server and the response to the client. This *decreases* response time and cuts down on the workload of the servers since the load balancer is handling the interaction w/o ever involving a server.
### Prioritization & QoS
Load balancers can prioritize running certain applications over others. They can also do *Content Switching* which allows them to run certain applications on *certain servers* and can switch which servers run which applications.
## Scheduling
### Round Robin
When a new query comes in, it's forwarded to the *next server on the list* (the last server to have gotten a forwarded request). The next query that comes in gets forwarded to the next server after that, and so on. *Each server is selected in turn* so they each get the same amount of load.
#### Weighted Round Robin
Prioritizes one server over the others (or servers). For example, the first server may get *twice the load* of the others.
#### Dynamic Round Robin
The load balancer *keeps track of the current load of each server*. When a request comes in, it sends it to the server *with the lowest use* (instead of the last server to have gotten a request).
### Active/ Active
> [!Note]
> Round Robin and Active/ Active can be used simultaneously

If one server fails, the others are configured to be able to pick up the load and continue operation *without any impact* to end-users.
### Active/ Passive
In this type of configuration, some servers are active and others are on *standby*. When one of the active servers fails, a passive server *is activated and takes its place*.
## Affinity
Affinity, when it comes to load balancers, describes the need for certain applications to communicate with users *using the same instance*. In other words, the user of that application is *'stuck'* to the same server as the application. Also called:
- Source Affinity
- Sticky Session
- Session Persistence
### Session ID
Tracking whether or not a user is communicating w/ an application over the same server can be done through *[IP-addresses](../../PNPT/PEH/networking/IP-addresses.md)* + port numbers, and/ or *session IDs*. When User A sends a request, the load balancer will forward it to sever 1 (for instance). When User B sends a request, the load balancer may forward it to server 2. *If User A sends another request, the load balancer will recognize their source IP and port and know that the request is from an earlier session, then forward that request to server 1 again*.

> [!Resources]
> - [Professor Messer](https://www.youtube.com/watch?v=_YXKeTbdyhk&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=107)
