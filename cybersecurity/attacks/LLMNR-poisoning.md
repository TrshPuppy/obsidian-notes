
# LLMNR Poisoning Attack:
An attacker can take advantage of [LLMNR](/networking/protocols/LLMNR.md) by spoofing as an authoritative source for name resolution.

## Mechanism:
![[Pasted image 20230222085032.png]]
-[Hacking Articles: Detailed Guide on Responder](https://www.hackingarticles.in/a-detailed-guide-on-responder-llmnr-poisoning/)
If a victim wants to connect to a shared drive w/i a network or system called `\\lemons` they send a request to the #DNS server. If the DNS server doesn't know how to resolve `\\lemons` (because it doesn't exist), the the victim will resort to sending #multicast request using #LLMNR instead.

The multicast request will query all listening interfaces on the network to see if any know how to resolve `\\lemons`. An attacker can spoof as an authoritative source for name resolution on the network in response to the multicast request.

The attacker will then request an [NTLM hash](/networking/protocols/NTLM.md) from the victim in order to "authenticate" the user.

The victim machine will then send their hashed credentials to the attacker.

>[!Links]
>[Hacking Articles: Detailed Guide on Responder](https://www.hackingarticles.in/a-detailed-guide-on-responder-llmnr-poisoning/)

