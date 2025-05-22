
# Kerberoasting
Kerberoasting is a technique used by an attacker for *privilege escalation* once they've already gained access to an [Active Directory](hidden/HTB-notes/active-directory.md) account.
## Basic Info
Once an attacker has already gained access to an AD user account, they can attempt to escalate their privileges using the [Kerberos](networking/protocols/kerberos.md) ticketing system.

To do this, the attacker uses the account they have access to (and its credentials) to *request a Kerberos ticket for an SPN*.
### What is an SPN?
In AD, an SPN is a Service Principle Name which refers to a user account that is tied to a service. Commonly, these types of accounts *have elevated privileges* in the AD which makes them high-value targets for priv-esc.

Additionally, any user in the AD can abuse the Kerberos authentication system to get the hash of any SPN accounts in use.
### Getting the Hash
With the already compromised user account, the attacker can request a *Kerberos ticket* for the target SPN. The ticket is encrypted *with the hash of the SPN's password*. Once the attacker retrieves the hash, it can be [brute-forced](cybersecurity/TTPs/cracking/brute-force.md) offline to get the *plaintext credentials* of the SPN.
### Reliability
This attack is *difficult to prevent* because the traffic and actions taken are done *by trusted AD accounts*. Additionally, no additional malware is involved or left behind on the target devices.
## Common Attack Flow
1. The attacker compromises an account in the AD (a Domain User)
2. Using this account, which is already authenticated, the attacker requests a Kerberos service ticket from the TGS (*Ticket Granting System*).
	a. A common tool used to check for SPNs on the Domain is `GetUserSPNs.py` from [impacket](../../exploitation/tools/impacket.md).
3. The attacker receives the ticket from the *Kerberos key Distribution Center* (KDC)
	a. Common tools used in this step of the attack include [Rubeus](https://github.com/GhostPack/Rubeus), and Impacket.
4. The attacker brute-forces the ticket offline to reveal the SPN's password using tools like [hashcat](../../cracking/tools/hashcat.md) or [john the ripper](../../cracking/tools/john.md).
5. With the password cracked from the hash, the attacker authenticates as the target SPN, *gaining all of the privileges associated*.

> [!Resources]
> - [CrowdStrike: Kerberoasting attacks](https://www.crowdstrike.com/cybersecurity-101/kerberoasting/)
> - [SBS Cyber: Kerberoasting...](https://sbscyber.com/blog/kerberoasting-the-potential-dangers-of-spn-accounts)
> - [GhostPack: Rubeus GitHub](https://github.com/GhostPack/Rubeus)
> - My other notes (linked throughout) can all be found [here](https://github.com/TrshPuppy/obsidian-notes)

