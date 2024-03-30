
# Technique: Heap Spraying
Init.
Heap Spraying is similar to [buffer-overflow](/cybersecurity/TTPs/exploitation/binary-exploitation/buffer-overflow.md) because it overwrites data in memory, but instead of putting more data into the space (beyond what the program has control over), it only inserts data into *certain parts* of the memory.

By spraying code into different parts of the memory you have access to, the hope is that you'll eventually inject code into *pre-dedicated spaces* which the computer is likely to read. One problem with this technique is that if the computer starts by executing your injected code halfway through its intended cycle, the computer will get confused and likely crash.

To prevent this, the code is wrapped in NOPs (no operations). When the computer comes across a NOP it will continue to read along the memory until it finds the start of executable code.

![](/cybersecurity/cybersecurity-pics/heap-spraying-1.png)
> [Andy Russel Cronin](https://andyrussellcronin.wordpress.com/2012/04/13/understanding-heap-spraying/)

> [!Resources:]
>  - [Andy Russel Cronin: Understanding Heap Spraying](https://andyrussellcronin.wordpress.com/2012/04/13/understanding-heap-spraying/)

