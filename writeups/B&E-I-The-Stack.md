
# B&E Pt. I: Understanding the Stack
## Buffer Overflows:
In general, buffer overflows *target stack frames in [memory](computers/memory/memory.md) allocated to data structures being used by a program.* The goal is to overwrite and *overflow* the stack frame in order to access memory not intended to be accessed by that frame.
## Vulnerability
Buffer overflows are possible when a program is able to write more data to the *buffer space* of a data structure/ subroutine than was intended. Writing past the bounds of the buffer causes *corruption of adjacent data on the call stack*. This will often cause the program to crash.

Additionally, stack memory *contains all the return addresses* for active function calls, so overflowing it *is more effective* at derailing an application than overflowing heap memory.
## Exploitation
Since the stack *stores all the return addresses* for functions on the call stack, the goal of most intentional buffer-overflows is to *overwrite the return address of a function w/ a pointer to malicious code instead* (which is also usually on the stack).
### Example
```c
#include <string.h>

void foo(char *bar)
{
   char c[12];

   strcpy(c, bar);  // no bounds checking
}

int main(int argc, char **argv)
{
   foo(argv[1]);
   return 0;
}
```
> [Wikipedia](https://en.wikipedia.org/wiki/Stack_buffer_overflow)

This [C](/coding/languages/c.md) code takes a command line argument and copies it to a variable called `c` *without checking how much space it will take up*. On execution *12 bytes of space* is allocated on the stack for the `c` variable. However in the C programming language *strings are terminated with a null byte* so really, if a string longer than 11 bytes is created, the 12 byte buffer will be overflowed:

![](/cybersecurity/cybersecurity-pics/buffer-overflow-1.png)
> [Wikipedia](https://en.wikipedia.org/wiki/Stack_buffer_overflow)

On the call stack, just under the frame allocated for `c` is the next frame, allocated for `*bar` and under that frame *is the return address for the function `foo()`*. 

An attacker can overwrite data all the way down to the return address and then replace the data there *with a pointer to their own code*. Usually this pointer is *the address of the original variable* (in this case `c`). So when `foo()` returns, *the [CPU](computers/cpu.md)* pops the return address off the stack *and goes to that address* to continue executing code.

![](/cybersecurity/cybersecurity-pics/buffer-overflow-2.png)
> [Wikipedia](https://en.wikipedia.org/wiki/Stack_buffer_overflow)

In this picture, The string of `AAAAA`'s represent the attacker-supplied data used for the overflow of `c`. Once an attacker *knows the amount of bytes it takes to reach and overwrite the return address*, they can replace part of their overflow string *with shellcode*. The CPU will return to the attacker-supplied address and begin executing the shellcode that's been inserted there. 
# Working Through an Example:
> [!Note]
> This is derived from my work through TsarSec's [course](https://taggartinstitute.org/courses/an-oral-history-of-binary-exploitation-defenses) on [Binary Exploitation](cybersecurity/TTPs/exploitation/binary-exploitation/buffer-overflow.md). Go check it out!
### Vulnerable Code
In order to understand the buffer overflow, we need to have code which will compile into a binary which is *vulnerable to buffer overflow*:
```c
#include <stdio.h>
#include <unistd.h>
#include <string.h>

void overflow() {
	char option[0x2];
	char name[0x100];
	int MAGIC = 0xe4ff;

	while(1) {
	memset(name, 0x00, 0x100);
	puts("Hey, whats your name!?\n");
	read(STDIN_FILENO, name, 4096);

	puts("Welcome ");
	puts(name);

	puts("is this name correct? (y/n)?");
	read(STDIN_FILENO, option, 2);
	if(option[0] == 'y' && option[1] == '\n') {
		break;
		}
	}
}

int main() {
	overflow();
	return 0;
}
```
In this code, the user inputs their name which is saved in the `name` buffer. It then asks the user if the inputed name is correct, then returns.

We can [compile](coding/compilation.md) the code using `gcc` into a binary. Then, (in linux), we can use [gdb](coding/gdb.md) to see/ work w/ the binary and step through execution. (P.S. there are additional steps which are necessary that I've purposefully left out. Go check out [TsarSec's course](https://taggartinstitute.org/courses/an-oral-history-of-binary-exploitation-defenses), it's free at the time of writing this :) ).
### GNU Debugger
To attach the binary to gdb, all we have to do is use the command `gdb ./vuln` (or whatever you named the binary). This brings us to the opening prompt. There are a lot of options here, but we can simply start by setting a breakpoint at `main()` and then using `run`:
```bash
┌──(hakcypuppy㉿kali)-[~/tsar]
└─$ gdb ./vuln_1                                            # <-------------
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
	<http://www.gnu.org/software/gdb/documentation>

For help, type "help".                                      
Type "apropos word" to search for commands related to "word"...

Reading symbols from ./vuln_1...
(No debugging symbols found in ./vuln_1)
(gdb) break main                                           # <-------------           
Breakpoint 1 at 0x4011fd
(gdb) run                                                  # <-------------
Starting program: /home/hakcypuppy/tsar/vuln_1
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x00000000004011fd in main ()
(gdb)
```
We can step through the execution by using `c` in the prompt (for continue). `gdb` will print the output from the binary as you go.
```bash
(gdb) c
Continuing.
Hey, whats your name!?

tiddies
Welcome 
tiddies

is this name correct? (y/n)?
```
#### Looking @ the memory
To see all the areas of memory our binary will be using we can use the `info proc mappings` command. This will show us where the program is stored in memory, where the [heap and stack](computers/memory/memory.md) are mapped to, where all the attached libraries are, etc:
```bash
(gdb) info proc mappings                                  
process 244655
Mapped address spaces:
          Start Addr           End Addr       Size     Offset  Perms  objfile
            0x400000           0x401000     0x1000        0x0  r--p   /home/hakcypuppy/tsar/vuln_1
      0x7ffff7dca000     0x7ffff7df0000    0x26000        0x0  r--p   /usr/lib/x86_64-linux-gnu/libc.so.6
      ...
      0x7ffff7f9f000     0x7ffff7fac000     0xd000        0x0  rw-p   
      0x7ffff7fc3000     0x7ffff7fc5000     0x2000        0x0  rw-p   
      0x7ffff7fc5000     0x7ffff7fc9000     0x4000        0x0  r--p   [vvar]
      0x7ffff7fc9000     0x7ffff7fcb000     0x2000        0x0  r-xp   [vdso]
      ...
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0  rwxp   [stack]
--Type <RET> for more, q to quit, c to continue without paging--
```
This is an edited list w/ some mappings removed but you can see that the program maps itself to `0x400000`, the stack is mapped to `0x7ffffffde000` (this is where it starts, and the `libc.so.6` library is at `0x7ffff7dca000`.
### Planning our Exploit
Since we know the `name` variable in the `overflow()` function is vulnerable, that's gonna be our target. *Every function on the stack* has a *saved instruction pointer* (saved `rip`) which tells the CPU where to go after the function has returned. 

If we look at the [assembly](coding/languages/assembly.md) output for `overflow()` we can get an idea of how the stack will look. To see this, we just use `disassemble overflow` in `gdb`:
![](/cybersecurity/cybersecurity-pics/buffer-overflow-3.png)
#### `call`
Looking at this we can see a few places where the `call` instruction is used in reference to functions in our c code. `call` does exactly what it sounds like: it calls the named function so it can be executed.

In the disassembled code for `overflow()`, `memset()` is the first subroutine being called in the `overflow()` function. Before we dive into what happens when a function is called, let's remember some things about the stack itself:
![](/cybersecurity/cybersecurity-pics/buffer-overflow-4.png)
##### Stack Things to Remember:
> [!Note]
> These guidelines apply to stack memory in x86 architectures

1. The stack spans a number of memory addresses in the [RAM](computers/memory/RAM.md).
2. The stack *grows downward*, i.e. frames are added *starting at the highest memory address, towards lower addresses*.
3. The "top of the stack" refers to the *lowest address in the stack*.
4. The 'bottom of the stack' refers to the *highest address in the stack*.
5. The first frame added to the stack *is the last frame which will be executed* by the [CPU](computers/cpu.md) (first in, last out or 'F.I.L.O.').
6. When data is written to a frame on the stack (i.e. to a variable in the function belonging to that frame) *the data is written towards higher memory addresses* (the opposite direction that frames are added)

Knowing these guidelines, let's work through the stack manipulation which happens when `main()` is called.
##### Stack Manipulation for `main()`
![](/cybersecurity/cybersecurity-pics/buffer-overflow-5.png)
This is the assembly code for `main()`. We can see that the first call instruction is for `overflow()`, but some things are happening before that which relate to the stack.
###### Function Prologue:
The first 2 lines in our assembly code for `main()` is the *Function Prologue*. This is a common sequence in assembly seen before functions are called.

In this sequence, the frame pointer stored in the `%rbp` register is *pushed to the stack*, then the stack pointer (saved in `%rsp` register) is copied into the `%rbp` register.

This sequence is important for flow control because when an *activation frame* (a frame which represents a function in the code) is pushed onto the stack or popped off, there is no way to control for the size of the frame. In other words functions in code have varying frame sizes. 

The CPU needs to know where to resume execution after a frame finishes, and since a frame can be of varying length, the address where the CPU needs to resume is not a fixed length from it's last position.
![](/cybersecurity/cybersecurity-pics/buffer-overflow-6.png)
The stack pointer *should always be pointed at the top of the stack* (or the address right after the end address of the last frame, in this case '5'). 

Before calling `overflow()` (and pushing its frame onto the stack), we need to push the current frame pointer (the address in the `%rbp` register), onto the stack. When that happens the stack will look something like this:
![](/cybersecurity/cybersecurity-pics/buffer-overflow-7.png)
Now that we've added a frame, we need to change the frame pointer to where the stack pointer is currently pointing. So we copy what's in the `%rsp` register into the `%rbp` register:
![](/cybersecurity/cybersecurity-pics/buffer-overflow-8.png)
Now the frame pointer and the stack pointer are pointing at the same place in memory. That's okay for now. We're going to call `overflow()`, push it onto the stack, and `overflow()` will take care of moving the stack pointer to its new position.
#### Disassembling `overflow()`
Before we update our stack picture, we have to understand what the `call` function does. In general, it calls the function being referenced, but there are 2 important parts which make that up:
1. `call` pushes the return address onto the stack (the address immediately following its own address)
2. It changes `rip` (the instruction pointer which is pointing at the assembly instructions) to the address of the function being called. *This ensures that the next instruction to be read by the CPU is the first instruction in the function being called* (which is `overflow()`).

So let's update our drawing so it more closely matches what's happening  in our overflow code:
![](/cybersecurity/cybersecurity-pics/buffer-overflow-9.png)
Compared to our last picture, I've updated the addresses (they will be slightly different on different computers). We now have an address saved in the `%rip` register (updated by the `call` instruction). And our stack and frame pointers are still pointing at the same address on the stack.

**TIP:** In order to get these values I put a breakpoint at `overflow` in gdb, then used the `info registers` command (`i r` works too) to see what was stored in all the registers:
![](/cybersecurity/cybersecurity-pics/buffer-overflow-10.png)
##### Updating `rsp`
We've finally made it to the overflow code! Now, can we finally update the stack pointer so its pointing where it should be? In fact, the frame pointer should probably be updated too.

Let's look at the first few instructions of `overflow()`:
```asm
(gdb) disassemble overflow
Dump of assembler code for function overflow:
   0x0000000000401146 <+0>:     push   %rbp
   0x0000000000401147 <+1>:     mov    %rsp,%rbp
=> 0x000000000040114a <+4>:     sub    $0x110,%rsp
...
```
The first three instructions look super familiar. That's because the same sequence that we saw earlier w/ the frame and stack pointers is happening again; the *Function Prologue*. The last step of the function prologue (`sub $0x110,%rsp`) is *making room for the variables in the function being called* by *subtracting* from the stack pointer.

The `sub` command stands for `subtract`, so this command is *subtracting `0x110` from the stack pointer*. Since this is in hex, `0x110` is 272 (256 + 16), and we're subtracting 272 from the value currently held in the `%rsp` register.

*Since the stack grows downward, subtracting from the stack pointer will move it down towards the top of the stack.* So the new address should be `7FFF FFFF DCC0` for stack pointer. We can now update our picture:
![](cybersecurity/cybersecurity-pics/buffer-overflow-11.png)
After this, a few more instructions are executed. For now, suffice it to say that the variables local to `overflow()` are created, allocated space, etc.. They all exist inside the frame for `overflow()` on the stack and we can expand the `overflow` frame to show that:
![](/cybersecurity/cybersecurity-pics/buffer-overflow-12.png)
And our stack now looks like this:

![](cybersecurity/cybersecurity-pics/buffer-overflow-11.png)
Read part II [here](https://trshpuppy.github.io/portfolio/writeups/buffer-overflow) to see how we use the `name` parameter to overflow the frame and inject our own shell code!

> [!Resources]
> - [Wikipedia: Buffer Overflows](https://en.wikipedia.org/wiki/Stack_buffer_overflow)
> - [TsarSec: Oral History of Binary Exploitation](https://taggartinstitute.org/courses/an-oral-history-of-binary-exploitation-defenses)
> - [Scott Wolchok: How to Read Assembly](https://wolchok.org/posts/how-to-read-assembly-language/)
