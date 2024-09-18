
# Proxies
Device which *sits between end users and the internet*. Facilitates *communication on behalf of the user*. It functions by forwarding requests from the client/ user to servers on the internet and returns their responses back to the user. Basically serves as a *gateway*.
## Functions
### Content Filtering
Proxies can filter content based on *configured policies* which allow them to block access to malicious websites or other content.
### Access Control
Can limit which users and/ or devices have access to specific resources on the internet.
### Anonymity
Can provide some anonymity to the user/ client by masking their [IP address](../../PNPT/PEH/networking/IP-addresses.md). Any traffic coming from the client *appears to be coming from the proxy*.
## Security Implications
### Privacy
Proxies can enhance security by *providing a barrier* between internal networks and the internet. They also can be configured to filter out malicious content. However, misconfiguration or compromise can cause *vulnerabilities.*
### Monitoring & Logging
Proxies often *log user activity*, which can aid in security monitoring. However, the logs must be carefully stored and managed to avoid unauthorized access to them.
### Single Point of Failure
If the proxy fails it can *disrupt access to the internet*. To prevent this, failovers and *redundancy* should be in place so connection isn't lost if the proxy fails.

> [!Resources]
> - Internship learning material

