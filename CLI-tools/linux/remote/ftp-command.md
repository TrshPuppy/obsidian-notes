
# FTP Command
A CLI utility which allows you to interact with [FTP](networking/protocols/FTP.md) servers on local and remote devices.
## Usage
```bash
ftp <username>@<IP Address>
```
### Anonymous FTP
Some hosts allow for *Anonymous FTP* to allow the public to access documents. In this case, a user can login using the `anonymous` username with a password of `anonymous` OR no password at all:
```bash
ftp 10.0.2.15
Connected to 10.0.2.15.    
220 (vsFTPd 3.0.3)  
Name (10.0.2.15:hakcypuppy): anonymous  
331 Please specify the password.  
Password:   # <------- password is 'anonymous'        
230 Login successful.
Remote system type is UNIX. 
Using binary mode to transfer files.  
ftp>        # <------- ftp shell
# OR
ftp anonymous@10.0.2.15
...
```
**NOTE:** The anonymous user *is not allowed to change directories or upload files*. But they can *copy files using the `get` command.*
### FTP Shell prompt
Once you have access to an FTP server, you're given a command prompt. You can use `-h` or `help` to get an output of available commands:
```bash
ftp> help
Commands may be abbreviated.  Commands are:
!               edit            lpage           nlist           rcvbuf          struct
$               epsv            lpwd            nmap            recv           sunique
account         epsv4           ls              ntrans          reget           system
append          epsv6           macdef          open            remopts         tenex
ascii           exit            mdelete         page            rename         hrottle
bell            features        mdir            passive         reset           trace
binary          fget            mget            pdir            restart         type
bye             form            mkdir           pls             rhelp           umask
case            ftp             mls             pmlsd           rmdir           unset
cd              gate            mlsd            preserve        rstatus         usage
cdup            get             mlst            progress        runique         user
chmod           glob            mode            prompt          send           verbose
close           hash            modtime         proxy           sendport       xferbuf
cr              help            more            put             set             ?
debug           idle            mput            pwd             site
delete          image           mreget          quit            size
dir             lcd             msend           quote           sndbuf
disconnect      less            newer           rate            status
ftp> 
```
#### `ls`
The `ls` command will list all of the files in the current directory.
#### `get`
The `get` command will allow you to download a file on the server w/ the syntax `get file.txt <LOCAL PATH>` where `<LOCAL PATH>` refers to where you want the file downloaded on your own computer.
#### `put`
The `put` command will allow you to *upload a file* to the server.
#### `status`
Lists information about the current connection:
```bash
ftp> status
Connected to 10.10.69.69.
No proxy connection.
Gate ftp: off, server (none), port ftpgate.
Passive mode: on; fallback to active mode: on.
Mode: stream; Type: ascii; Form: non-print; Structure: file.
Verbose: on; Bell: off; Prompting: on; Globbing: on.
Store unique: off; Receive unique: off.
Preserve modification times: on.
Case: off; CR stripping: on.
Ntrans: off.
Nmap: off.
Hash mark printing: off; Mark count: 1024; Progress bar: on.
Get transfer rate throttle: off; maximum: 0; increment 1024.
Put transfer rate throttle: off; maximum: 0; increment 1024.
Socket buffer sizes: send 16384, receive 131072.
Use of PORT cmds: on.
Use of EPSV/EPRT cmds for IPv4: on.
Use of EPSV/EPRT cmds for IPv6: on.
Command line editing: on.
Version: tnftp 20230507
```

> [!Related]
> - [FTP protocol](/networking/protocols/FTP.md)

> [!Resources]
> - `man ftp`

