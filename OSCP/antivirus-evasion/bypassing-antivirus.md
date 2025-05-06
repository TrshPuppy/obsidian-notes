
# Bypassing Antivirus Detection
Antivirus evasion comes in two categories: on-disk and in-memory. On-disk focuses on *modifying files stored on disk* to evade AV. In-memory focuses on avoiding the disk, which *reduces its chances of being detected*.
## On-Disk Evasion
On-disk evasion can be done via many different techniques. One of the earliest methods of evasions were "packers." Packers were designed to *reduce the size* of a piece of malware so that it didn't slow down network speeds or take up space on disk. 
### Packers
When a packer is used to obscure a piece of malware, the resulting file *is much smaller* and also *has a different file [hash](../../computers/concepts/cryptography/hashing.md)* compared to the original malware. Attackers commonly use packers like UPX (an open source packer). However, packing malware is not sufficient for evasion against modern AV systems.
### Obfuscators
Obfuscators make it harder to reverse engineer. They work by replacing instructions with ones which are *semantically equivalent*, inserting irrelevant or "dead" code, splitting and re-ordering functions, etc.. This technique is similar to techniques used by *software devs to protect intellectual property*, and is only slightly effective against signature AV detection.
### Crypters
Crypters alter executable code by adding in *decryption stubs* which restore the code to its original, malicious state upon execution. Decryption usually happens *in memory* and is one of the *most effective* evasion techniques.
### Others
Antivirus evasion usually requires some combination of all of these, as well as more advanced techniques including:
- anti-reversing
- anti-debugging
- [virtual machine](/computers/containers-vms/virtual-machines) emulation
## In-Memory Evasion
In-memory invasion, or "In-Memory Injections", or "[PE](../../computers/windows/PE.md) Injection" techniques are popular for evading AV systems, especially on [Windows](../../computers/windows/README.md) products. In-memory evasion focuses on *manipulating [Volatile Memory](../../computers/memory/memory.md#Volatile%20Memory)* instead of writing to disk. 

Most in-memory techniques rely on low-level coding languages like [C](../../coding/languages/C.md) and [C++](../../coding/languages/CPP.md). But here, we'll be discussing techniques using [powershell](../../coding/languages/powershell.md).
### Remote Process Memory Injection
In this technique the malware PE (portable executable) injects itself into another *valid PE* which is not malicious. The most common way to do this is through the Windows API. For example, you could use the `OpenProcess` function to obtain a valid `HANDLE` for a target process. With the `HANDLE`, you could then *allocate memory* in that process's context by calling a Windows API like `VirtualAllocEx`.  

Now that memory is allocated in the process, you could copy your malicious payload into it using `WriteProcessMemory`. Once the payload is copied into the process, it will be *executed in memory* via a separate [thread](../../coding/concepts/threading.md) using the `CreateRemoteThread` API.
### Reflective DLL Injection
[Reflective DLL Injection](https://andreafortuna.org//2017/12/08/what-is-reflective-dll-injection-and-how-can-be-detected/) differs from DLL Injection because, instead of using the `LoadLibrary` API, it loads a DLL stored by the attacker in a process's memory. Unfortunately, `LoadLibrary` *doesn't support loading a DLL from memory*, and there isn't a similar API in the Windows OS. So, attackers have to *write their own version* of the API.
### Process Hollowing
 [Process Hallowing](https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations) is where an attacker first launched a non-malicious process in a *suspended state*. When the process is removed from memory, it's replaced with a malicious executable image. Then, when the process is resumed, the malicious code will execute instead (but it will appear as if only the legitimate code executed).
### Inline Hooking
Inline hooking involves introducing a hook into memory (which is an instruction which redirects code execution into a function). The hook redirects the current execution into a function *which then points to malicious code*. After the malicious code is executed, the flow of execution gets returned to the modified function and resumes execution, making it look like only the original code was executing the whole time.

Hooking is *often used by rootkits*.


> [!Resources]
> - [UPX](https://upx.github.io/)
> - [Andrea Fortuna: Reflective DLL Injection](https://andreafortuna.org//2017/12/08/what-is-reflective-dll-injection-and-how-can-be-detected/) 
> - [I RedTeam: Process Hallowing](https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.