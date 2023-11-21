
we could also re-use an instruction in the binary itself that effectively performs a `jmp rsp;` or `call rsp;`.

jmp gadgets = same address

ROPgadget tool to find `jmp rsp` instrcuction (jump execution to the address saved in the stack pointer register)

since we know the offset of the stack pointer from the name variable in the overflow frame, we find the address of the `jmp rsp` and place it at then end or our buffer, and then our exploit code.

the cpu will go to the address of the jmp instruction and will execute the jmp to rsp instruction. the rsp is exactly where our exploit code starts on the stack

# NX and DEP
## no execute

## data execution prevention
DEP is windows

use info proc mappings for addresses of libc

used `find <1st address>,<last address>,"/bin/sh"` to find the bin/sh in the lib c pacakge

sh: 0xf7db5fc8

system 1: 0xf7c4c830

basically:
now we don't have execute permissions on the stack (we have r/w)

# ROP
ret instruction similar to pop rip (pops val from stack into rip register) + moves the sp up by 8

overwriting the saved ip on the stack:
	Means whatever we've overwritten it with gets *put into the ip register*

gadgets end with an return instruction == chain them together

https://t.co/wk2MbGF0xu