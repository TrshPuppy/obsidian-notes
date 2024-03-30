
# Unix Device Files
A device file in Unix is a file which is an *interface to a device driver*. It appears in the filesystem the same as other regular files but is special in that it *allows an application to interact with a device*. These files can also be referred to as 'device nodes'. Other [operating systems](computers/concepts/operating-system.md) employ similar interfaces, but this will focus on Unix specifically.
## Unix Device Nodes
In Unix, device nodes/files correspond to resources allocated by the [kernel](computers/concepts/kernel.md). In Unix, the resources are identified using two different numbers a *minor number*, and a *major number*. In general, the major number is meant to identify  the device driver and the minor number is meant to identify the device the driver controls.

The computer treats these nodes like standard system files and *interacts with them using system calls*. There are two different types of device files: Character devices, and Block devices. Unfortunately, the names for both are misleading due to some historical reason.
### Character Device Files
To avoid confusion, these devices are also called *'Raw Devices'*. They provide *direct access* to the hardware device. Contrary to the name, character devices *do not necessarily allow programs to read or write to these devices one character at a time*. Instead, it is dependent on the device to decide how it can be read or written to.
### Block Device Files
Block devices are different from character ones because they allow *reading and writing a block of any size to the device*. This means that a single character can be read or written to a block device. 

Because block devices *are buffered* a programmer doesn't know how long it will take for the data being written to pass from the kernel's buffer to the actual device. They also can't be sure in what order two separate writes will reach the device.

> [!Resources]
> - [Wikipedia: Device File](https://en.wikipedia.org/wiki/Device_file)