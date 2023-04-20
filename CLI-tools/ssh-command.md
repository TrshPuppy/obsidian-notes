# SSH Command
Command line tool to connect to devices via the [SSH](/networking/protocols/ssh) protocol.

## Usage:
To connect to a device via #ssh you need the IP of the target and the correct credentials:
```shell
# syntax: username@IP.Address
ssh tryhackme@10.10.194.63
The authenticity of host '10.10.194.63 (10.10.194.63)' can't be established.
ECDSA key fingerprint is SHA256:<key fingerprint>.
Are you sure you want to continue connecting (yes/no)? y
Please type 'yes' or 'no': yes
Warning: Permanently added '10.10.194.63' (ECDSA) to the list of known hosts.
tryhackme@10.10.194.63's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-1047-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Apr  7 18:17:24 UTC 2023

  System load:  0.0               Processes:             108
  Usage of /:   26.8% of 7.69GB   Users logged in:       0
  Memory usage: 23%               IPv4 address for eth0: 10.10.194.63
  Swap usage:   0%

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

tryhackme@linux2:~$ 
```
