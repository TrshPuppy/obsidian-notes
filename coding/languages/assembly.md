
# Assembly Code
Init.
> [!Note]
> 1. The following notes are fragmented, bc I'm completing parts as I need them, i.e. these notes are not complete.
> 2. These notes are based on *x86 architecure*.
## Registers
Registers in assembly code are basically equivalent to variables in other languages. However, unlike variables, there are a fixed number of them, they have standardized names, and they can only hold 64 bits-worth of information *at most*.

In [x86](computers/concepts/x86.md) architecture, there are *16 registers* including `rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, rr10, r11, r12, r13, r14,` and `r15`.
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
### `ret`
Return is normally the last instruction of a function/ routine/ sub routine. It's job is to:
1. Pop 8 bytes off the top of the stack (`$rsp`) and
2. Executes the instruction at the address it in the `rsp` it popped off the stack.
### The Function Prologue
The function prologue (and epilogue) is a sequence of  instructions commonly seen when a function is called in assembly code. If the architecture *has a base pointer and a stack pointer*, the function prologue does the following things:
1. Pushes the current base pointer (in `%ebp`/`%rbp`) onto the stack so it can be restored later.
2. Sets the value of the `%rbp` register (base pointer) to the current value of the stack pointer (in `%rsp`). Since the stack pointer is always pointed to the top of the stack, the base pointer will now also be pointing to the stop of the stack.
3. Move the stack pointer by increasing or decreasing its value (depending on the architecture. For example, in x86 architecture, the stack *grows downwards* so the pointer value will be decreased).
	- This is to *make room for the local variables of the function being called*.



> [!Resources]
> - [Wikipedia: X86-64](https://en.wikipedia.org/wiki/X86-64#Architectural_features)
> - [Scott Wolchok: How to Read Assembly](https://wolchok.org/posts/how-to-read-assembly-language/)
> - [TsarSec: ## An Oral History of Binary Exploitation Defenses](https://taggartinstitute.org/courses/an-oral-history-of-binary-exploitation-defenses)
> - [aldeid: x86 Assembly Instructions](https://www.aldeid.com/wiki/X86-assembly/Instructions)
