
# File Transfer Protocol
A client-server protocol used to communicate and transfer files using [[TCP]] between computers on a network. Users who wish to use an FTP connection need to have permission which is gained by providing credentials to the server.

Some *public* FTP servers *don't require credentials* which is called and allow users to login via the `anonymous` user. This is called *anonymous FTP*.
## Channels
There are two distinct channels:
### Command Channel:
FTP connection initiates the instruction and response.
### Data Channel:
where distribution of data happens b/w peers.
## Anonymous FTP
Sites can enable anonymous FTP so files are available to the public. Users can access the files w/o a password and with the username ``anonymous``. *Access is limited to copying files* and anonymous ftp *does not allow the user to navigate through directories*.
## FTPS
This is an extension of [SSL](SSL.md)
## SFTP
Uses [SSH](/networking/protocols/SSH.md) to provide encryption. Also provides file system functionality like *resuming interrupted file transfer*, directory listing, and remote file removal.

> [!Related]
> - #port-21
> - [FTP command](CLI-tools/linux/ftp-command.md)

> [!Resources]
> - [Hostinger: what is FTP](https://www.hostinger.com/tutorials/what-is-ftp)
> - [Geeks for Geeks: FTP](https://www.geeksforgeeks.org/file-transfer-protocol-ftp/)
> - [Wikipedia: FTP](https://en.wikipedia.org/wiki/SSH_File_Transfer_Protocol)


