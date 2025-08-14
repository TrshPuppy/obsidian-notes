---
aliases:
  - .lnk
  - .LNK
---

# .LNK Files
INIT
On [Windows](README.md) systems, `.lnk` files ("shortcut" files) are files which link to other files and applications in the file-system. They serve as *references* to other system locations and can even be embedded to provide object access. However, they're mostly used as "shortcuts."
## Format
The format of a `.lnk` file includes five structures, not all of which are required.
1. **SHELL_LINK_HEADER**: Mandatory structure containing essential information and flags for the rest of the file's structures.
2. **LINKTARGET_IDLIST**: Specifies the link target using the ItemID structure.
3. **LINKINFO**: Holds details about the location of the link target, including volume, serial number, and local paths.
4. **STRING_DATA**: Contains information about paths and interfaces for the link target. These structures are optional and are present only if the appropriate flag in LinkFlags (in ShellLinkHeader) is set.
5. **EXTRA_DATA**: Optional structures providing additional information about the link target.


> [!Resources]
> - [Sustainability of Digital Formats: Microsoft Windows Shortcut File](https://www.loc.gov/preservation/digital/formats/fdd/fdd000596.shtml?loclr=blogsig)
> - [ForensicsWiki: LNK (archive.org)](https://web.archive.org/web/20220519184752/https://forensicswiki.xyz/page/LNK)

> [!Related]
> - [OSCP Notes on Abusing .LNK files](../../OSCP/client-side-attacks/abusing-library-files.md)