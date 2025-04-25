INIT.
# Portable Executable
Portable Executable (PE) is a file format in [Windows](README.md) and UEFI environments for executable files (`.exe`, `.dll`, `.mui`, `.sys` etc.).  It is a structured container of data which gives the [OS](../concepts/operating-system.md) everything it needs to manage the executable code within it (including references to libraries, tables for importing and exporting APIs, resource data, and information on [threads](../../coding/concepts/threading.md)).
## Import Table
The import address table (IAT) is a lookup table which is used when the application calls a function from a *different module or library*. 

> [!Resources]
> - [Wikipedia: Portable Executable](https://en.wikipedia.org/wiki/Portable_Executable)