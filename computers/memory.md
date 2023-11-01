
# Computer Memory
Computer memory is divided into volatile and non-volatile memory. *Volatile memory* refers to memory which does not retain its state/value when the power is removed. *Non-volatile memory* is computer memory which retains its state/value after the power is removed.

There are also forms of computer memory which are considered *Semi-volatile*. (TMY: This is a weird term. Maybe you were thinking of data remanance which is the temporary retention of state after removing power. For example, DRAM has some data rememance, i.e. the electrical charge present in DRAM is still there for a bit even if you pull the DIMM out of the machine which enables things like cold boot attacks)
## Volatile Memory
Volatile memory *requires electricity to maintain the information it stores*. The most common type of volatile memory is DRAM [RAM](/computers/RAM.md) (random access memory). DRAM is the big, fast memory to hold working set data like program code or data just worked on or to be worked on soon. In constrast, there is SRAM which is used for on-chip CPU cache: less dense, more expensive, much faster

Memory can be used as [*Cache*](/computers/cache.md). Cache is a place to store recently used or soon-to-be needed things that need to be accessed quickly or to smooth impedence mismatch between componenets operating at different speeds. Cache is a purpose rather than a specific memory or storage technology. For example, DRAM is used as file cache for the file system data present on a hard drive, L2  and L3 CPU cache are different levels of SRAM cache to avoid off-chip DRAM access, on-board DRAM cache on a NIC to buffer network traffic before sending over the wire or sending back to host.
## Non-Volatile Memory
Non-volatile memory is "permanent" and is used to store information so that it persists even after the device is shut down (loses power).
### Read Only Memory (ROM)
Firmware (e.g. software embedded to the device) is typically stored in some kind of ROM. It generally *rarely change during the life of the device*. ROM *cannot be electronically modified* (usually). EPROM (erasable programmable ROM [erasable via UV light exposure]) is pretty old technology, used to be used for one-time-program purposes, i.e. it really will not need to be changed after installation, e.g. the sound bank in a speak-n-spell toy. EPROM technology is largely displaced by EEPROM (electrically erasable programmable ROM); this is used in the same capacity as other ROMs but is more easily erased and reprogrammed (electrically). Flash is a type of EEPROM.

ROMs are typically soldered into the PCB (means the memory *is hardwired* like in a circuit) as opposed to being removable. It cannot be changed (electronically) once it's been manufactured.

### Flash Memory
Flash memory is non-vol memory which *can be changed electronically*. There are 2 types of flash memory, *NAND* and *NOR* (named after logic gates). Besides that the two differ in how the information on them is written and accessed. (TMY: there a lot of differences. This is my research area). Both are historically based on floating gate.
#### NOR Flash
NOR flash is arranged in a way which *allows for fine-grained random access* at the granularity of a machine word. It's commonly *used for code execution*. However, the cells which store the data are larger *making writing and erasing slower* as well as *increasing the cost* (since more physical space is needed to store the same amount of data).

NOR flash can provide 100% 'good bits' for the life of the device, meaning the bits will always *reliably represent their intended value*.

#### NAND Flash
NAND flash uses a different gate architecture and has a larger access granularity. Additionally, executing code from NAND storage can only be done by *reading it into RAM* (whereas code execution from NOR memory is done directly ( this is called XIP [execute-in-place]). Today, NAND Flash is packaged in SSDs to serve as secondary storage rather than memory

NAND has a disparity between read/write granularity (page-size) and erase granularity (block-size); NAND also has limited endurance, i.e. finite program/erase (PE-cycles). These characterstics will vary based on the type of NAND technology (SLC, MLC, TLC, QLC which refer to "levels" per cell, i.e. bit density). SLC will have fastest performance and longest endurance while QLC will be much worse in exchange for higher bit density.

### Magnetic Storage Devices
This includes devices such as: (TMY: a bit strange to refer to secondary storage as "non-vol memory device". Secondary storage is defacto durable/non-volatile and is not used "as memory". It is the place to keeps things until you are ready to load stuff into memory))
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

