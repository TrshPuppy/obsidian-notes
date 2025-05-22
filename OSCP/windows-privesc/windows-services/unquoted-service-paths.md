---
aliases:
  - unquoted service paths
---
# Abusing Unquoted Service Paths Vuln
In the [Windows](../../../computers/windows/README.md) file system, file names can *optionally include a space* character. For example, pretend you have an application called `myExecutable.exe` which resides in `C:\temp\My Folder`. The [OS](../../../computers/concepts/operating-system.md) can resolve the path as `"C:\temp\My Folder\myExecutable.exe"` (quoted), or as `C:\temp\My Folder\myExecutable.exe`. 

When the file path *is surrounded in quotes* (quoted), then the OS will go directly to that path. When the file path *is not surrounded by quotes* (unquoted) then the OS *treats the space character as a delimiter* between `My` and `Folder` and will *search those as file paths*. In other words, when the file path is quoted, Windows follows this path:
```bash
C:\
|
--> My Folder\
    |
    --> myExecutable.exe
```
Compared to when the file path is unquoted, Windows follows this path:
```bash
C:\
|
1) --> My\
	|
	--> myExecutable.exe(?)
	|
  <--
2) --> My Folder\
	|
	--> myExecutable.exe
```
First, the OS will search for `myExecutable.exe` in `C:\My\`. If it doesn't find it there, *THEN* it will search in `C:\My Folder\`. 

In Windows, this is considered normal behavior, but it serves as the basis for the [_Unquoted service paths_](https://www.tenable.com/sc-report-templates/microsoft-windows-unquoted-service-path-vulnerability) vulnerability. An attacker can exploit this vulnerability simply by *creating the `C:\My\` directory and placing a malicious file called `MyExecutable.exe` there*.   
## How the Vuln is Introduced
When a [Windows Service](windows-services.md) is started the process for it is also created which means the [_CreateProcess_](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) function is used. The first parameter defined for this function is called `IpApplicationName` and is used to specify the name and (optionally) *the path to the executable file*. 

The `CreateProcess` function interprets the value of `lpApplicationName` from left to right. If the service's file path *is not quoted* and includes directories with spaces in their names, then when the function comes across a space, it has to determine whether the space indicates that the file path has ended and the next token is the first argument, or if the file path includes a space and the next token is still part of the file path.

So, if `lpApplicationName` is set to the (unquoted) value `C:\My Folder\myExecutable.exe`, then the function will stop on the space in `My Folder` and first check for the executable at the path `C:\My\`. If no executable is there, then it will next check for it at the path `C:\My Folder\`. 
### My Own Testing
So, if you create a service using `sc.exe` in a [PowerShell](../../../coding/languages/powershell.md) terminal, it's actually super hard to *QUOTE A SERVICE'S FILEPATH*. (fuck PS and Windows for real). 

I made my own little test. First, I used `sc.exe` to create a file called `test` in a folder named `\test folder`:
```powershell
PS> sc.exe create test -binpath= "C:\Users\Trash Puppy\Desktop\test folder\test.exe" -start= auto
[SC] CreateService SUCCESS
```
Then I tried to find the new service using the command *every single unquoted filepath vuln walk through* tells you to use to find vulnerable services:
```powershell
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v “C:\Windows\\” | findstr /i /v “””
```
Of course, this failed because PowerShell is a little BITCH about strings, and the `"""` at the end of the command was too much for it to handle (this is the an omen for the pain to come). 

Eventually I figured out that this is meant to be a *Command Prompt* command! So, I opened a second window for command prompt and it immediately worked.


> [!Resources]
> - [_Tenable: Unquoted service paths_](https://www.tenable.com/sc-report-templates/microsoft-windows-unquoted-service-path-vulnerability)
> - [_CreateProcess_](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text