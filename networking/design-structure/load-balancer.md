
# Load Balancers
Device or software application that distributes incoming network traffic across multiple servers to ensure no single server bears too much load. The primary function of a load balancer is to *optimize resource utilization*, maximize throughput, minimize response time, and *avoid server overload*.
## Functions
### Traffic Distribution
The load balancer receives incoming requests and distributes them across a *pool of servers* based on predefined algorithms. This is to try to distribute the workload evenly.
### Health Monitoring
Load balancers continuously monitor the health of servers. If a server becomes unavailable or unhealthy, the load balancer *is able to redirect traffic* to healthy servers, ensuring high availability.
### Scalability
Load balancers facilitate *horizontal scalability* by allowing additional servers to be added to the pool. This provides flexibility in responding to varying workloads and allows the servers to *adapt to increased traffic demands*. 
## Security
### DDoS Protection
Load balancers can absorb DDoS attacks by distributing the incoming traffic across multiple servers. This mitigates the damage done by DDoS attacks and *prevents a single point of failure*.
### [SSL](../protocols/SSL.md) Termination
Load balancers can handle SSL/TLS encryption and decryption. Normally, this encryption is done by backend servers. Offloading it onto load balancers takes this resource-heavy operation off the backend while also providing a *central point for managing SSL certificates*. 

It used to be that every server on the network would have to handle SSL encryption, and so they would all need their own certificates.
### Defending Against Server Exploits
By distributing traffic, load balancers can help *contain the damage* of a compromised server. Additionally, they often provide features like web application [firewalls](../../cybersecurity/defense/firewalls.md) to protect against common exploits.
### Session Persistence
Load balancers can maintain *session persistence* which ensures a user's requests are consistently directed to the same server.  This has to configured carefully to prevent *session related security issues and vulnerabilities.*

> [!Resources]
> - Internship learning material