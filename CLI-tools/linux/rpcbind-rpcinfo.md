
# `rpcbind` & `rpcinfo` Commands
These two commands can be used in conjunction to find and discover all the [RPC](/networking/protocols/RPC.md) services running on a target host.
## `rpcinfo`
```bash
NAME
     rpcinfo — report RPC information

SYNOPSIS
     rpcinfo [-m | -s] [host]
     rpcinfo -p [host]
     rpcinfo -T transport host prognum [versnum]
     rpcinfo -l [-T transport] host prognum versnum
     rpcinfo [-n portnum] -u host prognum [versnum]
     rpcinfo [-n portnum] [-t] host prognum [versnum]
     rpcinfo -a serv_address -T transport prognum [versnum]
     rpcinfo -b [-T transport] prognum versnum
     rpcinfo -d [-T transport] prognum versnum

DESCRIPTION
     rpcinfo makes an RPC call to an RPC server and reports what it finds.
```
### Usage:
#### `-p` probe:
The `-p` flag allows you probe the `rpcbind` service running on the host in order to discover a list of all the registered RPC programs. The command will *use version 2* or the RPC protocol w/ this flag.
#### `-t` RPC call w/ TCP:
Makes an RPC call to the specified program (using program number) and reports whether a response was received:
```bash
#          *port             *program #
rpcinfo -n 32768 -t 10.0.3.5 100024                
program 100024 version 1 ready and waiting
```
#### `-u` RPC call w/ UDP:
Same as the `-t` flag but uses UDP.
#### `-n` portnum:
This flag requires the port number (for the `-t` & `-u` flags) to be used instead of the port number provided by `rpcbind`. Using this flag *avoids calling the remote rpcbind to determine the address of the service*.
#### `-s` concise:
This flag will provide a more concise output of the scan as compared w/ other scans.
##### Comparison:
```bash
rpcinfo -p 10.0.3.5            
   program vers proto   port  service
    100000    2   tcp    111  portmapper
    100000    2   udp    111  portmapper
    100024    1   udp  32768  status
    100024    1   tcp  32768  status
```
```bash
rpcinfo -s 10.0.3.5
   program version(s) netid(s)                         service     owner
    100000  2         udp,tcp                          portmapper  unknown
    100024  1         tcp,udp                          status      unknown
```

## `rpcbind`
```bash
NAME
     rpcbind — universal addresses to RPC program number mapper

SYNOPSIS
     rpcbind [-adhiLlsr]

DESCRIPTION
     The rpcbind utility is a server that converts RPC program numbers into
     universal addresses.  It must be run‐ning on the host to be able to make
     RPC calls on a server on that machine.
```
### Usage:
#### `-h` host:
Give `rpcbind` a specific host to bind to *for UDP requests*.
#### `-r` random:
Tell `rpcbind` to *open random listening ports*. This is *required by `rpcinfo`* in order to work.

> [!Resources]
> - `man rpcinfo`
> - `man rpcbind`