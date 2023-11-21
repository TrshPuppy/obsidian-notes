
# GNU Debugger
Init.
## Usage
To attach `gdb` to a binary you can either use `gdb ./<binary name here>` or run the binary in another window and use `gdb -p $(pidof <process name here>)`. The first option will print the output of the binary to the `gdb` prompt and the other will print the output to the window from which the program was executed.
### Useful commands:
#### `break` (breakpoint)
Sets a breakpoint at a given point in the code. For example, you can break at the `main()` function by typing `break main`. Can also use `b main`.
#### `run`
The `run` command will start execution of the binary. It will also restart the execution if you've already stepped through part of it.
#### `c` (continue)
This will continue the execution to the next breakpoint (stepping through).
#### `n` (next)
Will step through.
#### `info proc mappings`
This command will show you all the memory areas, where they are, and what they're used for.
#### `disassemble <target>`
Get the assembly code for a given function/subroutine. For example, disassemble `main()`:
```bash
(gdb) disassemble main
Dump of assembler code for function main:
   0x00000000004011f9 <+0>:     push   %rbp
   0x00000000004011fa <+1>:     mov    %rsp,%rbp
=> 0x00000000004011fd <+4>:     mov    $0x0,%eax
   0x0000000000401202 <+9>:     call   0x401146 <overflow>
   0x0000000000401207 <+14>:    mov    $0x0,%eax
   0x000000000040120c <+19>:    pop    %rbp
   0x000000000040120d <+20>:    ret
End of assembler dump.
(gdb) 

```
#### `info registers`
`info registers` shows all the current values saved in the registers. You can also use `i r`.
#### `info frame`
Shows the current stack frame information.

> [!Resources]
> - [Source Ware: GNU Debugger](https://sourceware.org/gdb/current/onlinedocs/gdb.html/)

