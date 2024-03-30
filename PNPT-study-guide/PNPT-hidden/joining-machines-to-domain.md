
# Joining Machines to our LANDFILL Domain
Now that our domain and DC are set up, we can join our two other VMs to the domain. To do this, we need to *configure the network interface to treat the [domain controller](/computers/windows/active-directory/domain-controller.md)as the DNS server.*
## Domain Controller as DNS
To do this, just change the IPv4 interface to use the [IP address](/networking/OSI/IP-addresses.md) of the DC as the *preferred DNS server*.
![](/PNPT-pics/active-directory-8%201.png)
![](PNPT/PNPT-pics/active-directory-8%201.png)
Since the IP of my DC is `10.0.2.15`, that's what I set the DNS server value to on the two other computers. Additionally, I set static IPs for them within the same `10.0.2.0/25` network.
## Joining a Domain
Once the DNS is set, we want to join these computers to our `LANDFILL` domain. To do this:
1. search for 'domain' in the taskbar
2. click 'Access work or school'
3. click 'Connect'
4. click 'Join this device to a local Active Directory domain'
5. type 'LANDFILL' (or whatever your domain is called) into the prompt
6. Next, enter the credentials of one of the accounts you made in the server