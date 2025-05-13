
# Using `sshuttle`
[`sshuttle`](https://github.com/sshuttle/sshuttle) is a tool we can use for [remote dynamic port forwarding](remote-dynamic-port-forwarding.md). However, it requires *root privileges* and a python3 [HTTP](../../../www/HTTP.md) server, so in some cases it's bulkier than we need. `sshuttle` works by forcing traffic through an [SSH](../../../networking/protocols/SSH.md) tunnel. It works kind of like a VPN.
## Use
To use `sshuttle`, we need to give it the *[subnets](../../../PNPT/PEH/networking/subnetting.md) we want it to tunnel through*. For example, imagine we have the same scenario as described [here](../linux-tools/port-forwarding-scenario.md). Assume we've used [socat](../linux-tools/socat.md) to set up a regular [port forward](../../../networking/routing/port-forwarding.md) from `CONFLUENCE01`'s [WAN](../../../networking/design-structure/WAN.md) interface (on port `2222`). The port forward forwards traffic coming to port `2222` to port `22` on `PGDATABASE01`.

Now that the SSH port forward is live, we can specify that SSH connection as the one we want to use for `sshuttle` *from our Kali/attacking machine*:
```bash
kali@kali:~$ sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24
[local sudo] Password: 

database_admin@192.168.50.63's password: 

c : Connected to server.
Failed to flush caches: Unit dbus-org.freedesktop.resolve1.service not found.
fw: Received non-zero return code 1 when flushing DNS resolver cache.
```
Don't expect to see much output from `sshuttle`. What it should have done is set up routing on our Kali machine so *any requests we make to hosts and subnets* (we specified in the command) will be *pushed through the SSH connection*. 

To test it, we can run [smbclient](../../../CLI-tools/linux/remote/smbclient.md) to see if we can make a connection to the [SMB](../../../networking/protocols/SMB.md) share on the internal host `HRSHARES`:
```bash
kali@kali:~$ smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        scripts         Disk
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 172.16.50.217 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

kali@kali:~$
```

> [!Resources]
> - [`sshuttle`](https://github.com/sshuttle/sshuttle) 
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.
