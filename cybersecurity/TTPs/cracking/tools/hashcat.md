
# Hashcat
A CLI tool which is able to crack [hashes](/computers/concepts/cryptography/hashing.md) of various algorithms. It works by using techniques like [dictionary attacks](/cybersecurity/TTPs/exploitation/cracking/dictionary-attack.md), [combinator attacks](/cybersecurity/TTPs/cracking/compbinator-attack.md), [brute forcing](/cybersecurity/TTPs/cracking/brute-force.md), etc. against a provided hash.

**Hashcat uses your CPU to crack the hash**: so it can take a long time + may be too much work for your hardware depending on your system.
## Example (w/ MD5 hash)
```bash
hashcat -m 0 hashes /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 4.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.7, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-penryn-AMD Ryzen 5 5600X 6-Core Processor, 14614/29292 MB (4096 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c
Host memory required for this attack: 1 MB
Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

cd73502828457d15655bbd7a63fb0bc8:student  # <------------------ PASSWORD        
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: cd73502828457d15655bbd7a63fb0bc8
Time.Started.....: Fri Oct  6 14:07:31 2023 (0 secs)
Time.Estimated...: Fri Oct  6 14:07:31 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    65460 H/s (0.45ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 6144/14344385 (0.04%)
Rejected.........: 0/6144 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> iheartyou
Hardware.Mon.#1..: Util: 21%

Started: Fri Oct  6 14:07:27 2023
Stopped: Fri Oct  6 14:07:32 2023
```
## Usage
```bash
hashcat --help
hashcat (v6.2.6) starting in help mode

Usage: hashcat [options]... hash|hashfile|hccapxfile [dictionary|mask|directory]...
```
**NOTE:** Put the hash you want to crack into a file to give to hashcat.
### Example (w/ MD5)
```bash
hashcat -m 0 hashes /usr/share/wordlists/rockyou.txt
```
In this example:
- `-m`: `--hash-type`
- `0`: 0 is the type of algorithm which in this case is MD5
- `hashes`: the file containing *the hash we want to crack*
- `.../rockyou.txt`: the wordlist hashcat should use
### Example w/ [kerberos ticket](/networking/protocols/kerberos.md)
```bash
hashcat -m18200 tgt -a 0 /usr/share/wordlists/rockyou.txt
```

> [!Resources]
> - [Hashcat](https://hashcat.net/wiki/)
