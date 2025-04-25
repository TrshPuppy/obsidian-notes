---
aliases:
  - minifilters
---

# File System Filter Drivers
INIT
File system filter drivers ("minifilters") *intercept requests* made to file systems or other file system filter drivers. They're often used to supplement or extend the functionality of [antivirus engines](../../../OSCP/antivirus-evasion/README.md), backup agents, and [encryption](../../concepts/cryptography/README.md) products.
## Filter Manager
The [filter manager](filter-manager.md) (`FltMgr.sys`) is used to *develop filters*. It provides a framework for file I/O operations so developers don't have to worry about those complexities.

> [!Resources]
> - [Microsoft: Filter Drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/#file-system-filter-drivers)