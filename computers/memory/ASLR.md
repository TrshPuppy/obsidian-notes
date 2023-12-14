
# Address Space Layout Randomization
ASLR is a newer techniques used in the assignment of address space to a process. Before ASLR was implemented (by Linux in 2001), the addresses of key components/ data of a process were assigned predictably. This made it easy for attackers to hack a system using [buffer overflow](/cybersecurity/TTPs/exploitation/binary-exploitation/buffer-overflow.md) exploits because they could figure out the exact address that certain instructions etc. were going to be assigned to a program.

Even across different machines, the addresses assigned to vulnerable data in a process *were exactly the same*. So an attacker could craft an overflow to hijack sensitive parts of the process including *[machine code](/coding/languages/assembly.md) instructions* which *control the execution flow* of the program.
## Linux
In 2001 the Linux PaX project created a patch for the Linux kernel which was the first to implement ASLR. ASLR in Linux randomizes multiple *absolute memory locations* which were vulnerable to exploitation before randomization. These locations include:
- the [stack](/computers/memory/stack-and-heap.md)
- the [memory mapping segment](https://lxr.linux.no/#linux+v2.6.28.1/arch/x86/mm/mmap.c#L84)
- the [heap](/computers/memory/stack-and-heap.md)

> [!Resources]
> - [Wikipedia: ASLR](https://manybutfinite.com/post/anatomy-of-a-program-in-memory/)
> - [Many but Finite: The Anatomy of a Program in Memory](https://manybutfinite.com/post/anatomy-of-a-program-in-memory/)
> - [Linux Cross Reference: mmap.c](https://lxr.linux.no/#linux+v2.6.28.1/arch/x86/mm/mmap.c#L84)

