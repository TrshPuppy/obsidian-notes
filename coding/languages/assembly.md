
# Assembly Code
Init.
> [!Note]
> 1. The following notes are fragmented, bc I'm completing parts as I need them, i.e. these notes are not complete.
> 2. These notes are based on *x86 architecure*.
## Registers
Registers in assembly code are basically equivalent to variables in other languages. However, unlike variables, there are a fixed number of them, they have standardized names, and they can only hold 64 bits-worth of information *at most*.

In [x86](computers/x86.md) architecture, there are *16 registers* including `rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, rr10, r11, r12, r13, r14,` and `r15`.
### Nomenclature
Registers can be seen w/ either an `e` or `r` in their names. Registers w/ an `e` (such as `eax`) are 'extended', meaning they are *32 bits wide*. Registers used to be smaller (8, 16 bytes). So registers starting w/ an `e` are 'extended' b/c they're larger than the original register lengths.

Registers named starting w/ an `r` are *64 bits wide*.
### `rbp`: (frame pointer)
In x86 architecture, the `rpb` is the frame pointer.
### `rsp`: (stack pointer)
The `rsp` register saves the address of the *top of the stack* (i.e. the next available memory in the stack for a frame to be placed).
## Instructions
Again, these will be filled in over time, fragmented for now:
### `call`
In general, the `call` instruction is responsible for calling a function in the code. It has two operations:
1. Pushes the return address (*the address immediately after the call*), onto the stack. This becomes the 'saved instruction pointer'.
2. Changes the value of `eip` (instruction pointer) to the call destination (the address of the function being called). *This ensures that the next instruction to be read by the CPU is the first instruction in the function being called*
#### `sub`
Subtracts a value from a target (like a register). Ex:
```asm
sub    $0x110,%rsp
```

> [!Resources]
> - [Wikipedia: X86-64](https://en.wikipedia.org/wiki/X86-64#Architectural_features)
> - [Scott Wolchok: How to Read Assembly](https://wolchok.org/posts/how-to-read-assembly-language/)
> - [TsarSec: ## An Oral History of Binary Exploitation Defenses](https://taggartinstitute.org/courses/an-oral-history-of-binary-exploitation-defenses)
> - [aldeid: x86 Assembly Instructions](https://www.aldeid.com/wiki/X86-assembly/Instructions)
