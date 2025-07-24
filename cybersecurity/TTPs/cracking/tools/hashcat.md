
# Hashcat
A CLI tool which is able to crack [hashes](/computers/concepts/cryptography/hashing.md) of various algorithms. It works by using techniques like [dictionary attacks](../dictionary-attack.md), [combinator attacks](/cybersecurity/TTPs/cracking/compbinator-attack.md), [brute forcing](/cybersecurity/TTPs/cracking/brute-force.md), etc. against a provided hash.

**Hashcat uses your CPU to crack the hash**: so it can take a long time + may be too much work for your hardware depending on your system.
## Usage
```bash
hashcat --help
hashcat (v6.2.6) starting in help mode

Usage: hashcat [options]... hash|hashfile|hccapxfile [dictionary|mask|directory]...
```
**NOTE:** Put the hash you want to crack into a file to give to hashcat.
### `--show` To get a cracked hash:
```bash
┌──(root㉿kali)-[/home/trshpuppy/oscp/medtech/hashes]
└─# hashcat --show -m 1000 wario.hash
fdf36048c1cf88f5630381c5e38feb8e:Mushroom!
```
### Benchmarking
You can benchmark hashcats [Hash Rate](../../../../OSCP/password-attacks/README.md#Hash%20Rate) by using benchmarking mode with `-b`. The benchmark will be based on whatever hardware is available in the system. In the output example below, the only available hardware is the Intel *[CPU](../../../../computers/concepts/CPU.md)*. If there is a GPU present, hashcat would base the values on that.
```bash
hashcat -b
hashcat (v6.2.5) starting in benchmark mode
...
* Device #1: pthread-Intel(R) Core(TM) i9-10885H CPU @ 2.40GHz, 1545/3154 MB (512 MB allocatable), 4MCU

Benchmark relevant options:
===========================
* --optimized-kernel-enable

-------------------
* Hash-Mode 0 (MD5)
-------------------

Speed.#1.........:   450.8 MH/s (2.19ms) @ Accel:256 Loops:1024 Thr:1 Vec:8

----------------------
* Hash-Mode 100 (SHA1)
----------------------

Speed.#1.........:   298.3 MH/s (3.22ms) @ Accel:256 Loops:1024 Thr:1 Vec:8

---------------------------
* Hash-Mode 1400 (SHA2-256)
---------------------------

Speed.#1.........:   134.2 MH/s (7.63ms) @ Accel:256 Loops:1024 Thr:1 Vec:8
```
### Rule-Based Attacks
 According to the [Hashcat wiki](https://hashcat.net/wiki/doku.php?id=rule_based_attack) rule-based attacks *are the most accurate and efficient*:
```bash
┌──(root㉿kali)-[/home/trshpuppy/oscp/medtech/hashes]
└─# hashcat -m 1000 wario.hash /usr/share/wordlists/rockyou.txt --force -r /usr/share/hashcat/rules/best64.rule
hashcat (v6.2.6) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu--0x000, 2910/5884 MB (1024 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 77

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

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 1104517645

fdf36048c1cf88f5630381c5e38feb8e:Mushroom!

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: fdf36048c1cf88f5630381c5e38feb8e
Time.Started.....: Thu Jun 26 16:19:49 2025, (2 secs)
Time.Estimated...: Thu Jun 26 16:19:51 2025, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Mod........: Rules (/usr/share/hashcat/rules/best64.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 24538.1 kH/s (3.08ms) @ Accel:512 Loops:77 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 65364992/1104517645 (5.92%)
Rejected.........: 0/65364992 (0.00%)
Restore.Point....: 847872/14344385 (5.91%)
Restore.Sub.#1...: Salt:0 Amplifier:0-77 Iteration:0-77
Candidate.Engine.: Device Generator
Candidates.#1....: musicall -> mngebo
Hardware.Mon.#1..: Util: 97%

Started: Thu Jun 26 16:19:48 2025
Stopped: Thu Jun 26 16:19:53 2025
```
## Examples
### (w/ MD5 hash)
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
> - [Hashcat: Rule-based Attacks](https://hashcat.net/wiki/doku.php?id=rule_based_attack)
