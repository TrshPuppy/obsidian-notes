INIT
# NTUSER.DAT File
The NTUSER.DAT file is a file on [Windows](README.md) computer that *stores information about a user's session* including profile settings, preferences and other sensitive information. They are very useful in forensics because they store a lot of information about the user and their historical actions on a computer. 
## Information in `NTUSER.DAT`
Each user has their own `NTUSER.DAT` *hive* in the registry. Each key in the hive stored different information about the user and their actions on the computer. 
### Search phrases 
Any search phrases the user entered into Windows Explorer. Accessed via the `WordWheelQuery` key which is stored in the [registry](registry.md) path:
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
```
### Files Accessed
Files accessed and their paths. `NTUSER.DAT` stores path information in a few different registry keys:
#### `TypedPaths` key
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
```
Records paths manually entered by the user into the Windows Explorer address bar, including local paths, network shares, and sometimes URLs
#### `RecentDocs` key
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```
Lists recently accessed documents, organized by file extension, helping determine which files were opened. Each file extension *has its own subkey* like `.dox`, `.pdf` etc.
#### `File MRU` key
```
NTUSER.DAT\SOFTWARE\Microsoft\Office\<Version>\<Application>\User MRU\...\File MRU
```
Tracks recently accessed documents in *Microsoft Office* applications, providing full file paths and individual timestamps.
#### `OpenSavePidlMRU` key
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
```
Tracks files and folders accessed via Open and Save dialog boxes, providing full path information.
### Processes
The `Run` key in `NTUSER.DAT` stores information about *programs on the machine which are configured to execute automatically when the user logs in*.
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run
```

> [!Resources]
> - [CyberDojo: NTUSER.DAT Forensic Analysis](https://cyber-dojo.co/unlocking-windows-forensics-a-deep-dive-into-ntuser-dat-analysis/)