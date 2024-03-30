
# Anatomy of Memory
[Computer memory](/computers/memory/memory.md) can be broken down into volatile and non-volatile types. The difference between the two is whether the information being stored *persists after the device loses power*.

[Buffer Overflows](/cybersecurity/TTPs/exploitation/binary-exploitation/buffer-overflow.md) are executed on volatile memory in the [RAM](/computers/memory/RAM.md). Specifically they target memory *temporarily allocated* to a running program. In a basic sense, a buffer overflow allows an attacker *to write data beyond the intended storage boundaries* of a function call or variable in the vulnerable code.
## Stack
Stack memory is memory allocated in RAM during the execution of a program. It's used for running programs and tracking the functions and variables in the code.

The stack has a *last in, first out* (LIFO) structure, meaning its units are organized in a literal stack. If there are three objects on the stack, the second object *cannot be executed or referenced until the object above it is gone*.
### Stack Frames
Also known as "activation frames", stack frames are the units which make up the stack during program execution. They contain subroutines/ functions and variables defined in and used by the program. The first frame on the stack is *the 'main' function* of the program (wherever execution enters).

When a program is compiled into machine code/ assembly, it generates instructions for the [CPU](/computers/concepts/cpu.md) to follow when executing the program. Part of these instructions include *how stack frames should be created and managed* when functions are called during execution.

On execution, the CPU follows these instructions and *allocates memory in the RAM* to create stack frames. Each stack frame corresponds to a function call and contains all of the required information (including local variables, function parameters, return addresses, etc.).

The remaining frames on the stack are collectively called the *call stack* because they are made as functions are called throughout the program.

When the subroutine/ function of the currently executing stack frame *returns*, the stack frame *gets popped off the top of the stack* and the variables local to it are erased.
## Heap
Similar to the Stack, the Heap refers to volatile memory in RAM which is allocated during the execution of a program. The stack and heap differ in that the heap is meant to temporarily hold data which persists beyond the scope of a single subroutine/ function.

For example, if a program needs to track a single variable across multiple function calls, then heap memory will be allocated to manage that variable instead of stack. This allows the program to reference/ access the variable whenever it needs rather than it having to queue it in a stack/ LIFO structure.
### Structure
The structure of the heap *allows you to access variables/ data stored in it in any order*. This allows values to be accessed by different subroutines throughout the program, however *adding and removing items is more complicated* (and so uses more resources).

> [!Resources]
> - [Wikipedia: Call stack](https://en.wikipedia.org/wiki/Call_stack)
> - [Geeks for Geeks: Intro to Stack Memory](https://www.geeksforgeeks.org/introduction-to-stack-memory/#)
> - [Alex Hyett: Stack vs Heap Memory](https://www.youtube.com/watch?v=5OJRqkYbK-4)

> [!My previous notes (linked in text)]
> - You'll find them all [here](https://github.com/TrshPuppy/obsidian-notes)
