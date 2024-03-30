
# IOCTL (input/ output control)
Init.
IOCTL is an abbreviation for *input/ output control*. In computing, it usually refers to a *system call for device I/O*. An IOCTL takes a parameter which specifies a *request code*. The request code determines the effect the call will have and are commonly specific to the device. For example, the device driver for a CD-ROM would take an ioctl with a request code to *eject a disk* (which is an action specific to CD-ROMs).

The ioctl system call is specific to Unix and Unix-like systems (including Mac) but other [operating systems](/computers/concepts/operating-system.md) have similar concepts like `DeviceIoControl` in Windows.