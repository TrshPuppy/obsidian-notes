
# Subdomain Takeover
Subdomain takeover is a technique in which an attacker takes advantage of a forgotten subdomain, claims it, and uses it to host malicious content.

## Characteristics:
One way to tell if a subdomain is abandoned is via a `CNAME`, `A`, `MX`, `NS`, and `TXT` records (etc.). For example, if the owner of `victim.com` owns a second domain `secondvictim.com`, they may have a `CNAME` record to reference the second domain:
```
www.victim.com --> secondvictim.com
```
If `secondvictim.com` expires, then it's available for registration by anyone. 

If the `CNAME` record doesn't get deleted from the `victim.com` DNS zone, then whoever registers `secondvictim.com` will gain full control over `victim.com`.

> [!Resources]
> - [OWASP: Test for Subdomain Takeover](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)
> - [Cloudflare: DNS CNAME Record](https://www.cloudflare.com/learning/dns/dns-records/dns-cname-record/)
