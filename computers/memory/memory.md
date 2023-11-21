# Computer Memory

Computer memory is divided into volatile and non-volatile memory. _Volatile memory_ refers to memory which does not persist then the computer is shut off. _Non-volatile memory_ is computer memory which retains its state and persists even after the computer is turned off.

There are also forms of computer memory which are considered _Semi-volatile_.

## Volatile Memory

Volatile memory _requires electricity to maintain the information it stores_. The most common type of volatile memory is [RAM](computers/memory/RAM.md) (random access memory).

[_Cache_](computers/memory/cache.md) is another form of volatile memory. Unlike RAM cache is used to store _frequently needed_ information to avoid having to get the information elsewhere (using slower routes).

## Non-Volatile Memory

Non-volatile memory is "permanent" and is used to store information so that it persists even after the device is shut down (loses power).

### Read Only Memory (ROM)

Also known as _firmware_ this type of non-volatile memory is usually used for storing software which will _rarely change during the life of the device_. ROM _cannot be electronically modified_ (usually).

Read-only usually means the memory _is hardwired_ like in a circuit. It cannot be changed (electronically) once it's been manufactured.

### Flash Memory

Flash memory is non-vol memory which _can be changed electronically_. There are 2 types of flash memory, _NAND_ and _NOR_ (named after logic gates). Besides that the two differ in how the information on them is written and accessed.

#### NOR Flash

NOR flash is arranged in a way which _allows for random access_, meaning individual addresses are faster to access and read. It's commonly _used for code execution_. However, the cells which store the data are larger _making writing and erasing slower_ as well as _increasing the cost_ (since more physical space is needed to store the same amount of data).

NOR flash can provide 100% 'good bits' for the life of the device, meaning the bits will always _reliably represent their intended value_.

#### NAND Flash

NAND flash uses _smaller cells_ so more information can be stored per physical unit of space. However, the architecture _does not allow for random access_ so reading NAND-stored information is slower. Additionally, executing code from NAND storage can only be done by _shadowing it into RAM_ (whereas code execution from NOR memory is done directly).

NAND memory also tends to have "bad blocks" i.e. ~2% of the bits when shipped are assumed bad, and more fail over the lifetime of the device.

### Magnetic Storage Devices

This includes non-vol memory devices such as:

- Hard Disk Drives (HDD)
- Solid State Drives (SSD): similar to HDD but is _faster and more durable_
- Floppy Disks
- Magnetic tape

### Optical Discs

Information stored usually on a flat, disc-shaped object. The data is written to it in the form of _physical variations on the surface_. Optical discs are read using _a beam of light_, OR transmissivley (the light shines through the disc and detected on the other side.

> [!Resources]
>
> - [Wikipedia: Computer Memory](https://en.wikipedia.org/wiki/Computer_memory)
> - [Wikipedia: Read-Only Memory](https://en.wikipedia.org/wiki/Read-only_memory)
> - [Embedded: Flash 101](https://www.embedded.com/flash-101-nand-flash-vs-nor-flash/)
> - [Wikipedia: Optical Disc](https://en.wikipedia.org/wiki/Optical_disc)
