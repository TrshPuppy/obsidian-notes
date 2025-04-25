---
aliases:
  - antivirus
---
# Intro to Antivirus Systems
Antivirus software is primarily designed to recognize malware based on *signatures* which uniquely identify each specific piece of malware. There are different types of signatures with different characteristics. Some are *file hash summaries*, some use *binary sequence* matching, etc.. 
## Signatures
Each Antivirus Engine has its own *signature language*. The language is used for representing *different characteristics* of a piece of malware. Two signatures can be developed which *identify the same piece of malware*. For instance, one signature could be developed to target the malware *on disk* while the other is developed to target the malware via its *network communication*.
### YARA
One example of a signature language is [YARA](https://github.com/VirusTotal/yara). YARA is an open source tool created by Victor Alvarez from [Virus Total](../../cybersecurity/TTPs/recon/tools/reverse-engineering/Virus-Total.md):
> YARA is a tool aimed at (but not limited to) helping malware researchers to identify and classify malware samples. With YARA you can create descriptions of malware families (or whatever you want to describe) based on textual or binary patterns. Each description, a.k.a. rule, consists of a set of strings and a boolean expression which determine its logic.
### Limitations
Signatures are developed/written based on *known threats*, which gives them the disadvantage of not being able to detect new or modified malware. However, newer AV engines have tried to make up for this by integrating [ML](../../computers/concepts/AI/ML.md) (machine learning) usually via an ML engine which is *queried whenever an unknown file is discovered* on the system. 

Most of these ML engines *operate in the cloud* though, which means if the connection between the machine and the cloud provider is interrupted, they become useless. Additionally, *internal enterprises* don't usually have the option of an internet connection, leaving them without ML capabilities.

Lastly, having an AV engine which requires too much computing resources to run properly impacts the systems' usability.
### EDR & SIEM
Endpoint Detection and Response ([EDR](../../cybersecurity/defense/EDR.md)) was developed to make up for the limitations of Antivirus. EDR systems *generate security telemetry*  which it usually forwards to a Security Information and Event Management ([SIEM](../../cybersecurity/defense/SIEM.md)) system. Telemetry and data is collected *from every host on the network* and rendered by the SIEM so security teams can gain insight into past and current attacks on the organization.
## AV Engines & Components
Most AV Engines work by fetching signatures from the vendor's database which resides on the internet. Signature definitions are then stored locally in the AV's signature database. The AV's main database is then used to supplement information to other sub-engines
### Sub Engines
Most AV Engines are made up of the following sub-engines:
- File Engine
- Memory Engine
- Network Engine
- Disassembler
- Emulator/ Sandbox
- Browser Plugin
- Machine Learning Engine
Each works simultaneously to with the signature database to *rank specific events* as either *benign, malicious, or unknown*.
#### File Engine
Responsible for scheduled and real-time file scans. 
##### Schedule Scans:
File engine parses the entire file system, sending each file's *metadata or data* to the Signature Engine.
##### Real-time Scans
Detects and reacts to *new file actions* like downloading, writing to, etc.. To detect file actions in real-time, the File Engine requires identifying events *from the [kernel](../../computers/concepts/kernel.md) level* via a [minifilter](../../computers/windows/file-system/filter-drivers.md). Because of this, modern AV Engines *need to operate from both the kernel and user land* to validate a system.
#### Memory Engine
The memory engine *inspects each processes' memory space* at runtime for signatures or *suspicious API calls*. The memory engine's purpose is to detect *memory injection attacks*
#### Network Engine
Inspects network traffic incoming and outgoing for well-known *signatures*. If a signature is detected the network engine will *attempt to block* any network communication from the malware (like to a [C2](../../cybersecurity/TTPs/c2/C2.md) server).
#### Disassembler Engine
Malware often tries to hinder detection by using [encryption](../../computers/concepts/cryptography/README.md) and decryption techniques to modify and conceal itself. AVs combat this by *disassembling the malware* and loading it into a *sandbox*. 

The disassembler engine translates binary machine code into [assembly](../../coding/languages/assembly.md) to try and reconstruct the original code and identify any encoding or decoding routines within it
##### Sandbox
A sandbox is an isolated environment in the AV where malware can be loaded and executed *without posing a threat to the system*. Once malware is unpacked in a sandbox, it can be analyzed for signatures.

Most browsers are protected by a sandbox and modern AV systems take andvantage of this by employing *browser plugins* to get better visibility into web traffic and and malicious software that gets executed in the browser. 
## Detection Methods
AV systems use a few methods for detecting malware and may employ them differently depending on their *signature language*.  Common methods include:
- Signature-based
- Heruistic-based
- Behavioral
- Machine Learning
### Signature-based
Signature based detection is considered "restricted list" because it can only detect *known malware signatures*. Once if finds a malware signature in the environment, the offending files are *quarantined*. 
#### Limitations
Signatures are based mostly on file [hashes](../../computers/concepts/cryptography/hashing.md) or or patterns based on binary values belonging to a specific malware. This means that changing even one byte of a file will change its hash value and disrupt the binary patterns it may have had. To make up for this, AV manufacturers have developed other ways of detection.
### Heuristic
Heuristic detection uses rules and algorithms to determine if a specific action *is considered malicious*. To analyze a piece of software for malicious heuristic markers, the AV will step through the *[instruction set](../../coding/languages/assembly.md#Instructions)* and attempt to disassemble the machine code into assembly code, and then potentially into source code.

The goal of heuristic detection is to analyze the program calls made throughout the malware to determine if the actions it takes programmatically are potentially malicious.
### Behavioral
Behavioral detection is kind of similar to heuristic, but instead of looking at the internal programmatic actions of the malware in question, it runs the malware in an emulated environment and analyzes the actions and behaviors it makes externally.
### Machine Learning
ML detection adds ML algorithms to increase the AV system's ability to detect *unknown threats* (I'd like to look more into if this is actually good at detecting UNKNOWN threats). It does this by analyzing *metadata* and comparing a submitted sample against *all of the previously submitted samples*. Most ML implementations also utilize *cloud* computing. Whenever the model is unable to determine whether a sample is benign, it will query its cloud ML counterpart.