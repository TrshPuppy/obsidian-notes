
# SecLists
[SecLists](https://github.com/danielmiessler/SecLists) is a collection of wordlists which can be used in multiple steps of the kill chain. It includes lists which can be used for [dir busting](/cybersecurity/TTPs/recon/directory-enumeration.md), [password cracking](/cybersecurity/TTPs/exploitation/cracking/password-cracking.md), [subdomain enumeration](/PNPT/PEH/recon/hunting-subdomains.md), [credential stuffing](/PNPT/PEH/exploit-basics/credential-stuffing.md) etc..
## RAFT & Robots Disallowed
[RAFT](https://code.google.com/archive/p/raft/) was a tool built in 2011 which created wordlists using the `robot.txt` file of websites (which tell spiders where *not* to index for a site.

Since RAFT is old and unmaintained, it's been integrated into SecLists. The RAFT lists in SecLists are organized into 4 families, all named beginning with `raft.*`:
1. directories
2. extensions
3. files
4. words

Each family includes a small, medium, and large wordlist. Each wordlist has a lowercase copy. For example, the RAFT lowercase, large directories list is `raft-large-directories-lowercase.txt` (in SecLists/Discovery/Web-Content).
### [Robots Disallowed](/cybersecurity/tools/scanning-enumeration/wordlists/robots-disallowed.md)
Robots Disallowed is a currently maintained and updated tool similar to RAFT.

> [!Resources]
> - [SecLists GitHub Repo](https://github.com/danielmiessler/SecLists)
> - [Sec-IT Blog: Wordlists](https://blog.sec-it.fr/en/2021/03/02/web-wordlists/)
> - [RAFT tool](https://code.google.com/archive/p/raft/)
> - [Robots Disallowed GitHub](https://github.com/danielmiessler/RobotsDisallowed)
> - My other notes (linked throughout the text) can all be found [here](https://github.com/TrshPuppy/obsidian-notes)
