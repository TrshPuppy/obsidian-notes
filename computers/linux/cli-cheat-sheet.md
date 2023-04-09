
# Linux CLI Cheat Sheet
A quick reference for Linux commands:

## Filesystem:
| Command | Purpose |Notes|
|-|-|-|
|touch|create a file| takes only one argument, the name of the file, and creates a blank file|
|mkdir| create a folder|
|cp|copy a file or folder|takes 2 args: the name of the existing file, and the name you wish to assign to the new file|
|mv| move a file or folder|| takes 2 args like `cp`, can also be used to rename a file bc it ==modifies== the second file
|rm|remove a file or folder| `rm` is enough to remove a file, to remove a directory use `rm -R`
|file|determine the type of a file|
|find|find a file or folder in the filesystem|
|grep| find a specific string within a file, folder, or filesystem|

### Root Directories:
#### /etc
common storage place for system files used by the OS. Contains *passwd*, *sudoers*, *shadow*, etc.

##### .shadow
is a hidden file in `/etc` which contains users and their passwords, stored with sha512 encryption.

#### /var
short for "variable" is a directory which is accessed and written by applications running on the system. `/var/log` usually contains log files created by services and  applications. 

#### /root
Home for the "root" system user (instead of the root user's home directory being in `/home/root` like other users).

#### /tmp
A "volatile" directory which only stores data which needs to be accessed one or two times. Once the computer is restarted *the contents of this folder are cleared*.

##### For pentesting:
This folder is useful because any user has access to it, so it is an easy place to store things like scripts, etc. which you need during a pentest.

## Users & Permissions:
|cmd|purpose|notes|
|-|-|-|
|su|switch user| use the `-l` (login) switch to inherit other characteristics of the target user including changing the environment variables|

## Text Editors:
### Nano
#nano is a terminal text editor (has to be installed on a bare-bones shell set up).

#### Usage:
```bash
nano <filename>
```
Creates a file with the `<filename>` name and launches nano with the file, opened and ready to be modified.

#### Supported features:
These features can be used w/i nano by pressing the `Ctrl` key + the desired switch:
- Searching for text: `^W`
- Copy and pasting: `M-6`
- Jumping to a line number: `^_`
- Finding out the current line number: `^C`

### Vim
#vim

## Transferring files
### wget
Allows you to download files from the web using [HTTP](/networking/protocols/HTTP.md). Just need to supply #wget with the address of the resource.
```bash
wget https://assets.tryhackme.com/additional/linux-fundamentals/part3/myfile.txt
```

Can also use [curl](/CLI-tools/curL.md)

### SCP
#SCP or "secure copy" is a way to transfer files via SSH (so the files are encrypted and transferred over an authenticated connection).
```shell
# copy a file from host machine to target machine:
scp important.txt ubuntu@192.168.1.30:/home/unbuntu/transferred.txt

# copy a file from target machine to host machine:
scp ubuntu@192.168.1.30:/home/ubuntu/documents.txt notes.txt
```

> [!Links:]
> [THM Linux Fundamentals pt. 3](https://tryhackme.com/room/linuxfundamentalspart3)

