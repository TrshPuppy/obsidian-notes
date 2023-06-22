
# Metasploit
#metasploit Framework is an open-source set of tools which can be used for information gathering, scanning, exploitation, exploit development, post exploitation, etc.
- Primary use is for ethical hacking/ #penetration-testing

## Main components:
### [msfconsole](msfconsole.md)
Main CL interface.

### Modules:
anything which is packaged up and can be used to perform a specific task
- Types of Modules:
	- #exploits: piece of code which uses a vulnerability in a target system
	- #payload: the code which runs on a target system once it has been accessed maliciously (via an exploit)
	- #evasions: these modules attempt to evade antivirus software.
	- #post: Post modules are useful on the final stage of a penetration test b/c they help cleanup any leftover evidence from the exploit/ payload/ etc.

### Auxiliary:
Any supporting modules like scanners, crawlers, fuzzers, etc.
- in the msfconsole: ``auxiliary`` can be used to search for auxiliaries

### Encoders:
Allow you to encode an exploit and payload so that it won't be detected by a signature-based #antivirus 
- #signature-based-antivirus software use a DB of known threats which they use to detect suspicious files (by comparing them to the DB)
- #encoders sometimes have a limited success rate b/c antivirus software can use other checks to detect malicious software.

### NOPs (No Operations)
#nops literally do nothing and are used as buffers to achieve consistent payload sizes.
- represented by Intel #x86 CPU family

## Creating a #shell:
A shell is a persistent, interactive connection b/w an "attacker" (or Metasploit/ msfconsole) and the target machine which allows for the execution of commands on the target system.
- Metasploit offers payloads which can open shells on a target system

## Types of Payloads:
In msfconsole, under ``payloads`` there are 3 different directories:
1. #singles 
	- self-contained payloads which don't need to download any other components to run.
2. #stagers 
	- set up a connection channel b/w Metasploit and the target system.
	- used w/ "staged" payloads
		- #staged-payloads will upload a stager first on the target, then download the rest of the payload (the stage)
		- Useful because *the initial size of the payload will be smaller than the full payload*
3. #stages
	- Payloads downloaded by the stager, allows for larger payload sizes. 

### Tools:
- Stand-alone tools which help w/ vulnerability finding/ research/ assessment and penetration testing
	- ex: #mfsvenom
	- #pattern_create, and #pattern_offset
