This is part IV of my notes while working through [TsarSec's Course](https://taggartinstitute.org/courses/an-oral-history-of-binary-exploitation-defenses) on [binary-exploitation](https://github.com/TrshPuppy/obsidian-notes/blob/main/cybersecurity/TTPs/exploitation/binary-exploitation/buffer-overflow.md). You can find part II [here](https://trshpuppy.github.io/portfolio/writeups/binary-exploitation).
# Binary Exploitation Pt. 4: ROP Gadgets
In [part 3](https://trshpuppy.github.io/portfolio/writeups/nop-sleds) of my binary exploitation series we learned how to use a NOP sled to *increase the reliability* of our buffer overflow. However, the NOP sled technique is still *not 100% reliable* mostly due to the fact that, depending on where our entry point is on the stack, the vulnerable program's stack *may not be big enough for a large NOP sled*.

Fortunately, there's another technique we can use to ensure the CPU *jumps to the exact address of our shellcode*, and that's by high-jacking an instruction in the binary.
## Return Oriented Programming (ROP)
Return Oriented Programming is a binary exploit technique in which an attacker *uses machine instructions which are already present in memory* to exploit a program. This is usually *despite security defenses*.
### `jmp rsp` Instruction
The `jmp rsp`/ `call rsp` instruction is an instruction in the binary *which tells the CPU to go to the current address of the RSP*. These instructions are called 'jump gadgets' and *are always loaded into the same address* relative to the application's address space when it's loaded.

For our purposes, `jmp rsp` and/ or `call rsp` are ROP Gadgets and we're going to use them to *increase our exploit reliability.*
### Why is the Address Static?
We can bet on the fact that the address of `jmp rsp` will be the same between our machine and the target machine *as long as both machines are running the same OS*. Additionally, both machines would have to have defensive measures such as Address Space Layout Randomization ([ASLR](/computers/memory/ASLR.md)) turned off.

We're assuming these things are true. Without ASLR the OS *does not randomize the base addresses of the vulnerable program.* Instead, the OS loads the program into fixed, predictable addresses which are the same across machines.

There are additional considerations which go into this, including how the [compiler]() and [linker]() make decisions when the program is compiled, whether the output of compilation is deterministic, and whether or not the executables (on our machine and on the target machine) are identical or not. But, we're not going to worry about those right now.

Just assume that our target machine and our current machine are running the same OS and the layout of the address space of either *is not* randomized.
## Finding a ROP Gadget in the Binary
In order to find our ROP gadget, we can use a command line tool called `ROPgadget`. ROPgadget will list all the possible gadgets in our binary, and we can `grep` that list for our specific one (`jmp rsp`):
```bash
┌──(hakcypuppy㉿kali)-[~/tsar]
└─$ ROPgadget --binary ./vuln_1 | grep -i 'jmp rsp'
0x0000000000401150 : add bh, al ; cld ; jmp rsp
0x000000000040114e : add dword ptr [rax], eax ; add bh, al ; cld ; jmp rsp
0x0000000000401153 : cld ; jmp rsp
0x0000000000401154 : jmp rsp
```
In the output we can see that `ROPgadget` found 4 addresses in the binary where `jmp rsp` is mentioned. Let's use the address *that only lists `jmp rsp`* as an instruction(`0x0000000000401154`).
## Changing the Exploit Code
Remember when we did the NOP sled, our exploit ended up looking something like this on the stack:
![](/writeups/writeup-pics/Pasted%20image%2020231214121607.png)
![](/writeups/writeup-pics/Pasted%20image%2020231124142229.png)
Now that we have *the exact address* of our jump gadget, we can fix our exploit code so that our exploit will look like this:
![](writeups/writeup-pics/Pasted%20image%2020231214152234.png)
![](/writeups/writeup-pics/Pasted%20image%2020231214123032.png)
**REMEMBER**: That our *stack pointer* (which is where `jmp rsp` will tell the CPU to go and start executing from) *will be pointing directly at our shellcode*! This is because the `overflow()` function *will return first* before our overflow actually starts hijacking the execution flow.

The *stack pointer always points to the top of the stack*. So, **BEFORE** the CPU reads the address that we've overwritten the saved RIP frame with, the `overflow()` frame will be popped off the stack. Then the CPU will go to the address of saved RIP (which we've over-written). The saved RIP will be popped off the stack, and the stack pointer moved to the next frame (the frame we've overwritten with our shellcode).

When our ROP gadget `jmp rsp` is executed by the CPU, our stack will look like this:
![](/writeups/writeup-pics/Pasted%20image%2020231214124449.png)
When the CPU pops the saved RIP off the stack, and reads the address saved in there (`jmp rsp`), the CPU will go to that address, read the `jmp rsp` instruction, and *the current value in the `%rsp` register will be where the stack pointer is currently pointing* (our shell code).
### Our Code
Finally, let's look at our new exploit code:
```python
#!/usr/bin/env python3
from pwn import *

# we point saved rip to a 'jmp rsp' gadget:
new_rip = 0x0000000000401154

# construct shell code:
# let pwntools know we're dealing w/ a 64-bit target
context.update(arch="amd64")
shellcode = asm(shellcraft.amd64.linux.sh())

# construct payload
payload = b"A" * overflow_offset_rip
payload += p64(new_rip)
payload += shellcode

# connect to the vulnerable program
p = process("./vuln_1")

# send payload
pause()
p.sendafter(b"Hey, whats your name!?\n", payload)
p.sendafter(b"is this name correct? (y/n)?\n", b"y\n") 

p.interactive()
```
**GOTTEM!**

In the next part we'll learn more about ROP Gadgets and how to bypass some modern defenses of the stack!

Until then, Happy Holidays!

> [!Resources]
> - [Wikipedia: Return-oriented Programming](https://en.wikipedia.org/wiki/Return-oriented_programming)
> - [TsarSec: Oral History of Binary Exploitation](https://taggartinstitute.org/courses/an-oral-history-of-binary-exploitation-defenses)
> - My notes (linked throughout) you can find [here](https://github.com/TrshPuppy/obsidian-notes)


