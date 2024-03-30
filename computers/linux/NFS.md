
# Network Filesystem
Init.
## Mounting Shares via CLI
### Commands:
#### `mount`
**EXAMPLE**:
```bash
mount -t nfs4 10.0.2.7:srv/nfs /tmp/mount_dir
```
In this command `mount` is being used to mount the directory `srv/nfs` from a remote host to the `/tmp/mount_dir` directory on the local device.

The `-t` flag stands for 'type' and is being used here to specify that the remote dir to mount is an NFS directory.
#### `showmount`
`showmount` is a command which will list the public mounts of a target. The target can be remote:
```bash
showmount -d 10.0.2.7
```
In this command, `showmount` is given a remote host as a target and will list any public mounts on that target. The `-d` flag is used to specify that directories should be shown (the `-a` flag means 'all' and may show more mount types files/ shares).
#### `umount`
To *un-mount* a directory/ mount (that was previously mounted), you can use the `umount` command:
```bash
umount -t nsf4 -a
```
In this example `umount` is *unmounting all shares of NFS type*.
#### **IMPORTANT**
When mounting a share/ directory *do not mount it in your current working directory*. Instead, it's best to create a temporary folder/ mount point.

This is because while the share is mounted *you won't have access to other files in the local directory it's mounted to*. For example, if you mount a share to your local `~` directory:
```bash
mount -t nfs4 10.0.2.7:media/nfs ~/
```
everything in that directory (that's normally there *locally*) will be inaccessible while the remote share is mounted.


> [!Resources]
> [Linux Config: How to Configure NFS on Linux](https://linuxconfig.org/how-to-configure-nfs-on-linux)