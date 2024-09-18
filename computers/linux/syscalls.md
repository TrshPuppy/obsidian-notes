
# Syscalls
init.

Syscalls are implemented in Unix operating systems as a means to allow programs to request services from the [kernel](../concepts/kernel.md).

There are 300+ system calls categorized by their function. In general, functionality includes: process mgmt, file operations, device I/O, networking, and memory allocation, etc..
## Example Syscalls
### [ioctl](ioctl.md)
The `ioctl` syscall has to do with manipulating [device files](device-file.md). 

> [!Resources]
> - [The Linux Code: Golang Syscall Examples](https://thelinuxcode.com/golang-syscall-examples/)
> - [Filippo Valsorda: Searchable Linux Syscall Table](https://filippo.io/linux-syscall-table/)