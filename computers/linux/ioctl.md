
# IOCTL (input/ output control)
Init.
IOCTL is an abbreviation for *input/ output control*. In computing, it usually refers to a *[syscall](syscalls.md) for device I/O*. An IOCTL takes a parameter which specifies a *request code*. The request code determines the effect the call will have and are commonly specific to the device. For example, the device driver for a CD-ROM would take an ioctl with a request code to *eject a disk* (which is an action specific to CD-ROMs).

The ioctl system call is specific to Unix and Unix-like systems (including Mac) but other [operating systems](/computers/concepts/operating-system.md) have similar concepts like `DeviceIoControl` in Windows.
## Structure
The `ioctl` syscall takes an *op code/s* which dictate the type of action to be taken against the device file in question. For example, the op code `TCGETS` is used to request the current serial port settings for a specific termios structure from the kernel. 

> [!References]
> - [Debian Manpages: System Calls Manual](https://manpages.debian.org/unstable/manpages-dev/ioctl.2.en.html)
> - [Man7: TCGETS](https://man7.org/linux/man-pages/man2/TCGETS.2const.html)
> - [Man7: ioctl_tty](https://man7.org/linux/man-pages/man2/ioctl_tty.2.html)