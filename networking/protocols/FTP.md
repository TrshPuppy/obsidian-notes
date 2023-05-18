---
aliases: [FTP, file-transfer-protocol, ftp]
---
# File Transfer Protocol
#client/server protocol used to communicate and transfer files using [[TCP]] between computers on a network.
- users who wish to use an FTP connection need to have permission
	- permission is gained by providing credentials to the #FTP-server
		- some *public* #FTP-server s don't require credentials which is called #anonymous-ftp
- Two distinct channels:
	1. #command-channel : FTP connection initiates the instruction and response
	2. #data-channel: where distribution of data happens

#anonymous-ftp :
- sites can enable #anonymous-ftp so files are available to the public.
- users can access the files w/o a password and with the username ``anonymous``
- *Access is limited to copying files* anonymous ftp does not allow the user to navigate through directories

#SFTP: Secure FTP or SSH FTP:
- Extension of [SSH](/networking/protocols/SSH.md)

>[!related]
> #port-21
 [[ftp-command]]

>[!links]
>https://www.hostinger.com/tutorials/what-is-ftp
>
>https://www.geeksforgeeks.org/file-transfer-protocol-ftp/
>
>https://en.wikipedia.org/wiki/SSH_File_Transfer_Protocol

