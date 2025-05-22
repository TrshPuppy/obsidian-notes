
# PowerCat 
INIT
[PowerCat](https://github.com/besimorhino/powercat) is a command line tool similar to [netcat](../../cybersecurity/TTPs/exploitation/tools/netcat.md) but written for Windows and [powershell](../../coding/languages/powershell.md). Like netcat, it can be used for file transfer, as well as executing commands on the remote computer you use it to connect to.
## Installation
PowerCat is a powershell function. So, you can either copy it from GitHub into a `.ps1` file and then run it with `. ./powercat.ps1`, or you can load the function using a URL:
```ps1
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1')
```


> [!Resources]
> - [PowerCat GitHub](https://github.com/besimorhino/powercat)