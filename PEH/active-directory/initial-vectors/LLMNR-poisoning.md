
# LLMNR Poisoning
## What is [LLMNR](/networking/protocols/LLMNR.md)?
LLMNR (Link-Local Multicast Name Resolution) is a protocol used on a network to *help resolve hostnames* in the place of [DNS](/networking/DNS/DNS.md). It used to also be known as [NBT-NS](/networking/protocols/NBT-NS.md) but has since been updated in *most* systems.
### Mechanism
In order to resolve an [IP address](/networking/OSI/IP-addresses.md) to a hostname, LLMNR sends a *multicast packet* across the network to all of the listening interfaces. The packet askes each interface if they are the *authoritative hostname*. The Authoritative Hostname is the interface which is able to handle the resolution of the IP into a hostname.
## LLMNR Poisoning
LLMNR is *vulnerable* because it allows for [MITM](/cybersecurity/TTPs/exploitation/MITM.md) attacks like [LLMNR poisoning](/nested-repos/PNPT-study-guide/PEH/active-directory/initial-vectors/LLMNR-poisoning.md). In LLMNR poisoning, an attacker *poses as the authoritative hostname* in a network. They then wait for a victim machine to use LLMNR to find a hostname.

For example, if a victim machine sends an LLMNR request for a hostname like `\\lemons`, the multicast packet will go out to all listening interfaces including the attacker's fake authoritative server. When they get the packet, the attacker responds with a packet telling the victim computer "hey! I know how to connect to that hostname. Do you want the IP address?"

The victim machine will respond: "yes! I want that IP address," but in order to receive the IP address from the authoritative server, the victim has to authenticate w/i it by *sending [NTLM](/networking/protocols/NTLM.md) hash*. This hash includes a random number sent by the server, [encrypted](/computers/concepts/cryptography/cryptography.md) using the DES algorithm *and the user's password as the key.*

Since DES is *an old and vulnerable algorithm which is easy to crack*, the attacker can easily get the password of the victim by cracking the hash sent by the victim computer during authentication w/ their fake authoritative server.

> [!Resources]
> - My other notes (linked throughout), all of which can be found [here](https://github.com/TrshPuppy/obsidian-notes)