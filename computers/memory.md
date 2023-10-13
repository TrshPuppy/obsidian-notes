
# Computer Memory
Computer memory is divided into volatile and non-volatile memory. *Volatile memory* refers to memory which does not persist then the computer is shut off. *Non-volatile memory* is computer memory which retains its state and persists even after the computer is turned off.

There are also forms of computer memory which are considered *Semi-volatile*.
## Volatile Memory
Volatile memory *requires electricity to maintain the information it stores*. The most common type of volatile memory is [RAM](/computers/RAM.md) (random access memory).

[*Cache*](/computers/cache.md) is another form of volatile memory. Unlike RAM cache is used to store *frequently needed* information to avoid having to get the information elsewhere (using slower routes).
## Non-Volatile Memory
Non-volatile memory is "permanent" and is used to store information so that it persists even after the device is shut down (loses power).
### Read Only Memory (ROM)
Also known as *firmware* this type of non-volatile memory is usually used for storing software which will *rarely change during the life of the device*. ROM *cannot be electronically modified* (usually).

Read-only usually means the memory *is hardwired* like in a circuit. It cannot be changed (electronically) once it's been manufactured.
### Flash Memory
Flash memory is non-vol memory which *can be changed electronically*. There are 2 types of flash memory, *NAND* and *NOR* (named after logic gates). Besides that the two differ in how the information on them is written and accessed.
#### NOR Flash
NOR flash is arranged in a way which *allows for random access*, meaning individual addresses are faster to access and read. It's commonly *used for code execution*. However, the cells which store the data are larger *making writing and erasing slower* as well as *increasing the cost* (since more physical space is needed to store the same amount of data).

NOR flash can provide 100% 'good bits' for the life of the device, meaning the bits will always *reliably represent their intended value*.
#### NAND Flash
NAND flash uses *smaller cells* so more information can be stored per physical unit of space. However, the architecture *does not allow for random access* so reading NAND-stored information is slower. Additionally, executing code from NAND storage can only be done by *shadowing it into RAM* (whereas code execution from NOR memory is done directly).

NAND memory also tends to have "bad blocks" i.e. ~2% of the bits when shipped are assumed bad, and more fail over the lifetime of the device.
### Magnetic Storage Devices
This includes non-vol memory devices such as:
- Hard Disk Drives (HDD)
- Solid State Drives (SSD): similar to HDD but is *faster and more durable*
- Floppy Disks
- Magnetic tape
### Optical Discs
Information stored usually on a flat, disc-shaped object. The data is written to it in the form of *physical variations on the surface*. Optical discs are read using *a beam of light*, OR transmissivley (the light shines through the disc and detected on the other side.

> [!Resources]
> - [Wikipedia: Computer Memory](https://en.wikipedia.org/wiki/Computer_memory)
> - [Wikipedia: Read-Only Memory](https://en.wikipedia.org/wiki/Read-only_memory)
> - [Embedded: Flash 101](https://www.embedded.com/flash-101-nand-flash-vs-nor-flash/)
> - [Wikipedia: Optical Disc](https://en.wikipedia.org/wiki/Optical_disc)

