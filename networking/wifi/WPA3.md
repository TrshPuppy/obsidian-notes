---
aliases:
  - SAE
---
# WPA3
WPA3 is the most up to date standard for [WiFi](802.11.md) networks and was created as a more secure alternative to [WPA2](WPA-WPA2.md). According to Wikipedia:
> The new standard uses an equivalent 192-bit cryptographic strength in WPA3-Enterprise mode ([AES-256](https://en.wikipedia.org/wiki/AES-256 "AES-256") in [GCM mode](https://en.wikipedia.org/wiki/Galois/Counter_Mode "Galois/Counter Mode") with [SHA-384](https://en.wikipedia.org/wiki/SHA-384 "SHA-384") as [HMAC](https://en.wikipedia.org/wiki/HMAC "HMAC")), and still mandates the use of [CCMP-128](https://en.wikipedia.org/wiki/CCMP_\(cryptography\) "CCMP (cryptography)") ([AES-128](https://en.wikipedia.org/wiki/AES-128 "AES-128") in [CCM mode](https://en.wikipedia.org/wiki/CCM_mode "CCM mode")) as the minimum encryption algorithm in WPA3-Personal mode. [TKIP](https://en.wikipedia.org/wiki/Temporal_Key_Integrity_Protocol "Temporal Key Integrity Protocol") is not allowed in WPA3.
>
> The WPA3 standard also replaces the [pre-shared key](https://en.wikipedia.org/wiki/Pre-shared_key "Pre-shared key") (PSK) exchange with [Simultaneous Authentication of Equals](https://en.wikipedia.org/wiki/Simultaneous_Authentication_of_Equals "Simultaneous Authentication of Equals") (SAE) exchange, a method originally introduced with [IEEE 802.11s](https://en.wikipedia.org/wiki/IEEE_802.11s "IEEE 802.11s"), resulting in a more secure initial key exchange in personal mode and [forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy "Forward secrecy"). The Wi-Fi Alliance also says that WPA3 will mitigate security issues posed by weak passwords and simplify the process of setting up devices with no display interface. WPA3 also supports [Opportunistic Wireless Encryption (OWE)](https://en.wikipedia.org/wiki/Opportunistic_Wireless_Encryption "Opportunistic Wireless Encryption") for open Wi-Fi networks that do not have passwords. The Wi-Fi Alliance calls OWE "Wi-Fi CERTIFIED Enhanced Open"; Wi-Fi manufacturers often refer to it as "Enhanced Open" rather than OWE.
>
> Protection of management frames as specified in the [IEEE 802.11w](https://en.wikipedia.org/wiki/IEEE_802.11w-2009 "IEEE 802.11w-2009") amendment is also enforced by the WPA3 specifications.
## SAE 
SAE or Simultaneous Authentication of Equals is a password-based authentication that allows both parties to *prove they know the password without sending it over the wire*. SAE in WPA3 is used with the goal of *replacing the PSK* from WPA/WPA2 networks. SAE makes WPA3 more secure because it:
- prevents attackers from brute-forcing the password with offline attacks (like brute-forcing the [hand shake](WPA-WPA2.md#Authentication))
- requires active interaction w/ the AP for each client
- rate limits password attempts
### High-level Overview
In SAE the client and AP are treated as peers ("equals"). Neither side has the burden to prove the password first. Instead, they:
- use the password to generate a shared [cryptographic](../../OSCP/password-attacks/README.md) element
- exchange cryptographic commitments
- prove their knowledge of the password without revealing it
- derive a *session key*
All of these things happen *before the WPA 4-way handshake*.
### Step by Step
#### 1. Password → cryptographic element
Both the client and AP take:
- The Wi-Fi password
- The SSID
- Their MAC addresses
and derive a value called the **Password Element (PWE)** using elliptic curve math. This value is n*ever transmitted*.
#### 2. Commit exchange
Each side generates a **random secret** and a **public commitment**. They then exchange a **commit messages**  which contains a public elliptic curve value as well as a scalar. Example flow:
```bash
Client → AP : SAE Commit  
AP → Client : SAE Commit
```
#### 3. Shared secret creation
Using:
- the password-derived element
- their private random values
- the peer’s public value
Both sides compute the **same shared secret**. This is similar to [Diffie-Hellman](../../computers/concepts/cryptography/diffie-hellman.md) key exchange, but protected by the password. This exchange proves both sides can compute values derived from the password.
#### 4. Confirm messages
Each side sends a **confirm message** proving they derived the same key. If both confirms validate, **authentication succeeds**.
#### 5. WPA3 4-way handshake
After SAE completes, the connection continues with the normal Wi-Fi key establishment:
- Pairwise Master Key (PMK) derived
- WPA **4-way handshake**
- Session encryption keys created
Encryption usually uses **AES‑CCMP** or **GCMP‑256**.


> [!Resources]
> - [Wi-Fi Protected Access - Wikipedia](https://en.wikipedia.org/wiki/Wi-Fi_Protected_Access#WPA3)
> - [Simultaneous Authentication of Equals - Wikipedia](https://en.wikipedia.org/wiki/Simultaneous_Authentication_of_Equals)