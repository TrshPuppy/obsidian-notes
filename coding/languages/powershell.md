---
aliases:
  - PowerShell
---

# Windows PowerShell
PowerShell is the Windows scripting language environment, built on the [.NET](/computers/windows/.NET.md) framework. Because it is build using .NET it can execute .NET functions directly from the shell.

Most PowerShell commands (called *cmdlets*) are written in .NET and their outputs are  objects, which means PowerShell is *object-oriented*. Being object-oriented means that running cmdlets lets you perform actions ont he output object.

The syntax of a cmdlet is verb-noun, ex `Get-Command` is a cmdlet which lists all commands. Common verbs include
- Get
- Start
- Stop
- Read
- Write
- New
- Out
## Basic Commands
### Get-Help
Displays information about a cmdlet. By using the `-Examples` flag, you can see exactly how the command is used.
#### Syntax
`Get-Help <Command-Name>
### Get-Command
Lists all the cmdlets installed on the current machine. It allows for pattern matching
#### Syntax
`Get-Command Verb-*` or `Get-Command *-Noun`
- For example`Get-Command New-*` gets all the cmdlets with the verb "new"
```PowerShell
PS C\Users\Administrator> Get-Command New-*

CommandType     Name                            Version    Source
-----------     ----                            -------    ------
Alias           New-AWSCredentials              3.3.563.1  AWSPowerShell
Alias           New-EC2FlowLogs                 3.3.563.1  AWSPowerShell
Alias           New-EC2Hosts                    3.3.563.1  AWSPowerShell
Alias           New-RSTags                      3.3.563.1  AWSPowerShell
...
```
## Object Manipulation
Since the output of every cmdlet is an object, there are a few ways to manipulate the output
- Passing output of one cmdlet to another
- Using specific object cmdlets to extract information

The *Pipeline* `|` is used to pass output from one cmdlet to another, but instead of passing strings or text to the command after the pipe PS passes an object.

Like every object in coding, cmdlets have their own properties and methods. To view the properties/methods of a cmdlet, use `<cmdlet name> | Get-Member`.

Example
```PowerShell
PS C\Users\Administrator> Get-Command | Get-Member -MemberType Method

   TypeName System.Management.Automation.AliasInfo

Name             MemberType Definition
----             ---------- ----------
Equals           Method     bool Equals(System.Object obj)
GetHashCode      Method     int GetHashCode()
GetType          Method     type GetType()
ResolveParameter Method     System.Management.Automation.ParameterMetadata ResolveParameter(string name)
ToString         Method     string ToString()


   TypeName System.Management.Automation.FunctionInfo

Name             MemberType Definition
----             ---------- ----------
Equals           Method     bool Equals(System.Object obj)
GetHashCode      Method     int GetHashCode()
...
```
The `-MemberType` flag allows you to select b/w methods and properties.
### Creating Objects from Previous Cmdlets
One way to manipulate a cmdlet object is to pull out the properties from its output and create a new object from them. This can be done with the `Select-Object` cmdlet
```PowerShell
PS C\Users\Administrator> Get-ChildItem | Select-Object -Property Mode, Name

Mode   Name
----   ----
d-r--- Contacts
d-r--- Desktop
d-r--- Documents
d-r--- Downloads
d-r--- Favorites
d-r--- Links
d-r--- Music
d-r--- Pictures
d-r--- Saved Games
d-r--- Searches
d-r--- Videos
```
`Get-ChildItem` lists all of the files and folders in a file system drive. *P.S.* `get-childitem` can only recurse (with `-r` flag) through it's CHILDREN (and not its parents)
#### Select-Object flags
- `First` gets the first `x` object
- `Last` gets the last `x` object
- `Unique` shows the unique objects
- `Skip` skips `x` objects
### Filtering Objects
To retrieve objects with very specific values, you can use the `Where-Object` cmdlet to filter based on the value or properties
#### Syntax
`Verb-Noun | Where-Object -<Propery> <PropertyName> -<operator Value>`
`Verb-Noun | Where-Object {$_.PropertyName -operator Value}`

The second version uses `$_` to iterate through every object passed to the Where-Object cmdlet. 

The `-operator` is a placeholder for the following operator flags
- `-Contains` if any item in the property value is an exact match for the specified value.
- `-EQ` if the property value is the same as the specified value.
- `-GT` if the property value is greater than the specified value
- etc...
#### Example checking stopped processes
```PowerShell
Get-Service | Where-Object -Property Status -eq Stopped

Status   Name               DisplayName
------   ----               -----------
Stopped  AJRouter           AllJoyn Router Service
Stopped  ALG                Application Layer Gateway Service
Stopped  AppIDSvc           Application Identity
Stopped  AppMgmt            Application Management
Stopped  AppReadiness       App Readiness
...
```
`Get-Service` gets the services on a local or remote computer.
### Sort Object
In order to sort the output information of a cmdlet, you can pipe line the output of the cmdlet to the `Sort-Object` cmdlet.
#### Syntax
`Verb-Noun | Sort-Object`
Example sort the list of directories (default = alphabetically) from `Get-ChildItem`
```PowerShell
Get-ChildItem | Sort-Object

    Directory C\Users\Administrator

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        10/3/2019   511 PM                Contacts
d-r---        10/5/2019   238 PM                Desktop
d-r---        10/3/2019  1055 PM                Documents
d-r---        10/3/2019  1151 PM                Downloads
d-r---        10/3/2019   511 PM                Favorites
d-r---        10/3/2019   511 PM                Links
d-r---        10/3/2019   511 PM                Music
...
```
## PowerShell ISE
### Creating a new file in PS
Use `New-Item` with `-Path` set to `.` to make the file in the current directory
```PowerShell
New-Item -Path . -Name "test.ps1"
```
### Opening the file in PS ISE
```Powershell
powershell ise test.ps1
```
### Script to "Find a Password"
```PowerShell

```
## Useful Examples
### 1. Find a specific file
```PowerShell
get-childitem -recurse -erroraction silentlycontinue -include interesting-file* -File
```
### 2. Script to "count" number of matching items
```PowerShell
$count=0
foreach($output in (get-command | where-object -property commandtype -eq cmdlet)){
	$count+=1;
	set-content $count -path count.txt
}
```
### 3. Get MD5 Hash of a file
```PowerShell
get-filehash -algorithm md5 \intersting-file.txt
```
### 4. Get the current working deirectory
```PowerShell
get-location
Path
----
C\
```
### 5. Make a request to a web server
```PowerShell
invoke-webrequest google.com
```
ALSO
```powershell
iwr -uri 'http://address.com:PORT/file.txt' -Outfile file.txt
```
### 6. Script to decode Base64 encoded text
```PowerShell
$file = cat b64.txt
$decoded = [Convert]:FromBase64String($file)
-join($decoded -as [char[]])
```
### 7. Get total output length
```PowerShell
get-localgroup | measure 

Count     24
Average  
Sum      
Maximum  
Minimum  
Property 
```
### 8. Add to or Remove From $PATH
#### Add to `$ENVPATH`
```powershell
[Environment]:SetEnvironmentVariable("Path", $envPath + ";R\a-trshp-does-windows\Microsoft VS Code\bin\code.exe", "Machine") 
```
#### Remove from `$ENVPATH`
```powershell
foreach($path in ($envpath).split(";")){if($path -like "R\CS50\Microsoft VS Code\bin"){$new_path = $envpath.replace($path, "")};[System.Environment]:SetEnvironmentVariable("Path",$new_path,"Machine")}
```
### 9. Port scan an IP
```powershell
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
```
### 10. Encoding a command
Let's say you've got a [SQLi](../../cybersecurity/TTPs/exploitation/injection/SQLi.md) and you want to avoid detection while using it to execute a PowerShell command, you can use PowerShell's `-enc` to encode the command:
```powershell
powershell.exe -enc 
```
**NOTE** that PS's `-enc` expects the command to be a base 64 encoded *unicode string* (`UTF-16LE` to be specific). So, you can't just pipe your command to `base64` in your linux CLI and expect PS to understand it. Instead, you can use `iconv` to first convert the command string to Unicode, and then pipe it to `base64`:
```bash
echo -n "iwr https://example.com" | iconv -f UTF-8 -t UTF-16LE | base64 -w 0
```
- `echo -n`: prevents the new line character from being added to the command string
- `iconv -f UTF-8`: tells `iconv` that the input string is being encoded *from* UTF-8
- `-t UTF-16LE`: tells `iconv` to encode the input *to* UTF-16LE
- `base64 -w 0`: the `-w 0` disables wrapping

>[!Resources]
> - [THM PowerShell Room](https//tryhackme.com/room/powershell)

