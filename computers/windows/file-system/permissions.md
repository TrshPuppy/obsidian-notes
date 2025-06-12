INIT
# File Permissions in Windows
## Permissions Masks
Just like [linux file permissions](../../../PNPT/PEH/kali-linux/file-permissions.md), Windows uses file permission masks to set the permissions of files:

| Mask | Permissions             |
| ---- | ----------------------- |
| F    | Full access             |
| M    | Modify access           |
| RX   | Read and execute access |
| R    | Read-only access        |
| W    | Write-only access       |
You might also see:
- **N** - No access
- **D** - Delete access
- **DE** - Delete
- **RC** - Read control (read permissions)
- **WDAC** - Write DAC (change permissions)
- **WO** - Write owner (take ownership)
- **S** - Synchronize
- **AS** - Access system security
- **MA** - Maximum allowed
- **GR** - Generic read
- **GW** - Generic write
- **GE** - Generic execute
- **GA** - Generic all
- **RD** - Read data/list directory
- **WD** - Write data/add file
- **AD** - Append data/add subdirectory
- **REA** - Read extended attributes
- **WEA** - Write extended attributes
- **X** - Execute/traverse
- **DC** - Delete child
- **RA** - Read attributes
- **WA** - Write attributes
- **I**: (Inherit) - ACE inherited from the parent container.
- **(OI)** - Object inherit. Objects in this container inherits this ACE. Applies only to directories.
- **(CI)** - Container inherit. Containers in this parent container inherits this ACE. Applies only to directories.
- **(IO)** - Inherit only. ACE inherited from the parent container, but doesn't apply to the object itself. Applies only to directories.
- **(NP)** - Don't propagate inherit. ACE inherited by containers and objects from the parent container, but doesn't propagate to nested containers. Applies only to directories.
### ICACLS
![See my OSCP notes on `icacls`](../../../OSCP/windows-privesc/windows-services/hijacking-service-binaries.md#`icacls`)

> [!Resources]
> - [Microsoft: File Permissions](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)