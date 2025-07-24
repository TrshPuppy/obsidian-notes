---
aliases:
  - sharphound
---
INIT
# SharpHound
A companion tool to [BloodHound](BloodHound.md) which is used for collecting the information that BloodHound organizes and displays. Written in [C#](../../../coding/languages/C-sharp.md), SharpHound uses the Windows API and [LDAP](../../../networking/protocols/LDAP.md) namespace (like [LDAP-ADSI](../manual-enumeration/LDAP-ADSI.md)). For example, SH uses `NetWkstaUserEnum` and [`NetSessionEnum`](../manual-enumeration/PowerView.md#Digging%20into%20`NetSessionEnum`) to enumerate logged-on sessions. It also runs queries against the *Remote Registry Service*.
## Getting Started
You can get SH as a [PowerShell](../../../coding/languages/powershell.md) script, an executable, or you can compile it yourself. The current zip file for the PS script should be [here](https://github.com/SpecterOps/SharpHound/releases). Once the zip file is downloaded and unzipped, you can get it onto your target Windows machine and import it as a module:
```powershell
PS> powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows
PS> Import-Module .\Sharphound.ps1
```
### Running
#### `Invoke-BloodHound`
The first thing to do after importing is running `Invoke-BloodHound`. Using `Get-Help Invoke-BloodHound` will tell us more about it:
```powershell
PS> Get-Help Invoke-BloodHound
NAME
    Invoke-BloodHound

SYNOPSIS
    Runs the BloodHound C# Ingestor using reflection. The assembly is stored in this file.

SYNTAX
    Invoke-BloodHound [-CollectionMethods <String[]>] [-Domain <String>] [-SearchForest] [-Stealth] [-LdapFilter
    <String>] [-DistinguishedName <String>] [-ComputerFile <String>] [-OutputDirectory <String>] [-OutputPrefix
    <String>] [-CacheName <String>] [-MemCache] [-RebuildCache] [-RandomFilenames] [-ZipFilename <String>] [-NoZip]
    [-ZipPassword <String>] [-TrackComputerCalls] [-PrettyPrint] [-LdapUsername <String>] [-LdapPassword <String>]
    [-DomainController <String>] [-LdapPort <Int32>] [-SecureLdap] [-DisableCertVerification] [-DisableSigning]
    [-SkipPortCheck] [-PortCheckTimeout <Int32>] [-SkipPasswordCheck] [-ExcludeDCs] [-Throttle <Int32>] [-Jitter
    <Int32>] [-Threads <Int32>] [-SkipRegistryLoggedOn] [-OverrideUsername <String>] [-RealDNSName <String>]
    [-CollectAllProperties] [-Loop] [-LoopDuration <String>] [-LoopInterval <String>] [-StatusInterval <Int32>]
    [-Verbosity <Int32>] [-Help] [-Version] [<CommonParameters>]

DESCRIPTION
    Using reflection and assembly.load, load the compiled BloodHound C# ingestor into memory
    and run it without touching disk. Parameters are converted to the equivalent CLI arguments
    for the SharpHound executable and passed in via reflection. The appropriate function
    calls are made in order to ensure that assembly dependencies are loaded properly.

REMARKS
    To see the examples, type: "get-help Invoke-BloodHound -examples".
    For more information, type: "get-help Invoke-BloodHound -detailed".
    For technical information, type: "get-help Invoke-BloodHound -full".
```
#### `-CollectionMethod`
This flag tells SharpHound what method to use for collecting information. If you want to collect all information, then give the flag `All`. This will use all collection methods *accept for local group polices*. SH will automatically compile the data into [JSON](../../../coding/data-structures/JSON.md) files and then zip them for us so we can *exfiltrate* them more easily later.
#### Full Command
```powershell
PS> Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
```

> [!Resources]
> - [SharpHound PS script](https://github.com/SpecterOps/SharpHound/releases)