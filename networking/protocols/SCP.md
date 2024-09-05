
# Secure Copy Protocol
Init.

Copy files between devices using SSH. The syntax is very close to a regular [SSH](SSH.md) command with some caveats.
## Usage
```bash
# Basic Syntax
scp -i <identityfile> host:/file/location host:/file/destination

# Example
scp -r -i SSH-Private.pem root@<IP Address>:/root/screenshots/ ./screenshots 
```
In this example, the following flags mean:
- `-r` Recursive: use this if you want to copy over all of the contents *in a directory* on the remote machine
- `-i` Identity file: just like w/ the `ssh` command, this is the identify file you want to use
### Tips
 Use SSH command in history and change to `scp`
 - first host is the file you want
 - the second is the destination
 - you can push files (from your host to a server) just reverse order

> [!Resources]
> - [Wikipedia: SCP](https://en.wikipedia.org/wiki/Secure_copy_protocol)
> - [Geeks for Geeks](https://www.geeksforgeeks.org/scp-command-in-linux-with-examples/)i

```
scp -i <.pem file> root@d<IP address>:<remote file to grab> <local destination file> 

# recursive (for directories)
scp -r -i <.pem file> root@d<IP address>:<remote file to grab> <local destination file> 
```