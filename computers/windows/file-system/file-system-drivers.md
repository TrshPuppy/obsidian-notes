
# File Systems
INIT
In [Windows](../README.md), the file system is implemented as file system drivers which work *above the storage system*. They provide data storage and other features for users. 
## Types
Windows file systems can be either NTFS, ExFAT, UDF, or FAT32. Each type has its own features. There is also the Resilient File System (ReFS) which is only available on Windows Server 2012 and later versions.
### Comparison
|Feature|NTFS|exFAT|UDF|FAT32|
|---|---|---|---|---|
|Creation time stamps|Yes|Yes|Yes|Yes|
|Last access time stamps|No (see note below)|Yes|Yes|Yes (date only)|
|Last change time stamps|Yes|Yes|Yes|Yes|
|Last archive time stamps|No|No|No|No|
|Case-sensitive|Yes (option)|No|Yes|No|
|Case-preserving|Yes|Yes|Yes|Yes|
|Hard links|Yes|No|Yes|No|
|Soft links|Yes|No|No|No|
|Sparse files|Yes|No|Yes|No|
|Named streams|Yes|No|Yes|No|
|Oplocks|Yes|Yes|Yes|Yes|
|Extended attributes|Yes|No|Yes (on-disk only)|No|
|Alternate data streams|Yes|No|Yes|No|
|Mount points|Yes|No|No|No|

> [!Resources]
> - [Microsoft: File System](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/)
> - [Microsoft: Filesystem Comparison](https://learn.microsoft.com/en-us/windows/win32/fileio/filesystem-functionality-comparison)