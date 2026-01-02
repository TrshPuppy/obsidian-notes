
# NetExec (`nxc`)
A network service exploitation tool which automates assessing security of large networks.

## Shit that worked
### Spidering [SMB](../../../../networking/protocols/SMB.md) shares
Spider shares and download content.
```bash
nxc smb $ip -u '' -p '' -M spider_plus -o DOWNLOAD_FLAG=True
```

> [!Resources]
> - [NetExec Wiki](https://www.netexec.wiki/)
> - [GitHub](https://github.com/Pennyw0rth/NetExec)