
# Information Gathering: Enumerating a Target's Software
## Metadata
We can inspect the *metadata tags* of publicly available documents from our target. For example, if we find a PDF file hosted on the target's website, we can download it and then use some tools to examine the metadata attached to it. Metadata can include a lot of information like people's names, GPS coordinates, time and date the file was created, etc..
### `exiftool`
`exiftool` is a linux command line tool which, when provided a file, will extract the file's metadata. It can also be used to *wipe metadata* from a file. Assuming we downloaded a file from the target titled "brochure.pdf," using `exiftool` to inspect it would look like this:
```bash
cd Downloads 

exiftool -a -u brochure.pdf 
ExifTool Version Number         : 12.41
File Name                       : brochure.pdf
Directory                       : .
File Size                       : 303 KiB
File Modification Date/Time     : 2022:04:27 03:27:39-04:00
File Access Date/Time           : 2022:04:28 07:56:58-04:00
File Inode Change Date/Time     : 2022:04:28 07:56:58-04:00
File Permissions                : -rw-------
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.7
Linearized                      : No
Page Count                      : 4
Language                        : en-US
Tagged PDF                      : Yes
XMP Toolkit                     : Image::ExifTool 12.41
Creator                         : Stanley Yelnats
Title                           : Mountain Vegetables
Author                          : Stanley Yelnats
Producer                        : Microsoft® PowerPoint® for Microsoft 365
Create Date                     : 2022:04:27 07:34:01+02:00
Creator Tool                    : Microsoft® PowerPoint® for Microsoft 365
Modify Date                     : 2022:04:27 07:34:01+02:00
Document ID                     : uuid:B6ED3771-D165-4BD4-99C9-A15FA9C3A3CF
Instance ID                     : uuid:B6ED3771-D165-4BD4-99C9-A15FA9C3A3CF
Title                           : Mountain Vegetables
Author                          : Stanley Yelnats
Create Date                     : 2022:04:27 07:34:01+02:00
Modify Date                     : 2022:04:27 07:34:01+02:00
Producer                        : Microsoft® PowerPoint® for Microsoft 365
Creator                         : Stanley Yelnats
```
- `-a`: tells exiftool to display duplicated tags
- `-u`: tells exiftool to display unknown tags
From this output we're most interested in: the Creator, the Create Date, Creator Tool, and the Modify Date/Time. Regarding the operating system, since the document was created with Microsoft 365, and there is no mention of Mac or "macos", we can assume the operating system the file was created on was Windows.
## Client Fingerprinting
Basically this section says to create a canary token, put it in a phishing email, send it to the target, and if they click it, the canary token will tell you the victim's User-Agent which you can use to figure out the operating system.... Kind of dumb since we're just assuming the person is going to click the link, and that phishing is even in scope in the first place...

We didn't even talk about the most obvious trick: looking at the [TXT-record](../../networking/DNS/TXT-record.md) of the target's domain. But WHATEVER...

> [!Resources]
> - PEN 200 (I guess)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.