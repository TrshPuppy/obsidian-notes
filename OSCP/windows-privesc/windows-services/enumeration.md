# Enumerating Windows Services
There are a few commands you can run on the Windows host to  discover vulnerable services. Mostly, we'll use `net` and the services command (`sc.exe`)
## Manually
### Service Configuration
To query for the configuration of a service, run `sc.exe` with the `qc` flag:
```ps
C:\Users\admin>sc qc WinHttpAutoProxySvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: WinHttpAutoProxySvc
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : WinHTTP Web Proxy Auto-Discovery Service
        DEPENDENCIES       : Dhcp
        SERVICE_START_NAME : NT AUTHORITY\LocalService
```
### Current Status
Use the `sc`/ `sc.exe` command with the `query` flag to check the *current status* of a service:
```ps
C:\Users\admin>sc query WinHttpAutoProxySvc

SERVICE_NAME: WinHttpAutoProxySvc
        TYPE               : 30  WIN32
        STATE              : 4  RUNNING
                                (NOT_STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```
## Automated (Tools)
### winPEAS
You can use tools like [winPEAS](../../../cybersecurity/TTPs/actions-on-objective/tools/winPEAS.md) to check for service misconfigurations:
```ps
PS C:\Users\admin> .\winPEASany.exe quiet servicesinfo
   Creating Dynamic lists, this could take a while, please wait...
   - Checking if domain...
   - Getting Win32_UserAccount info...
   - Creating current user groups list...
   - Creating active users list...
   - Creating disabled users list...
   - Admin users list...
  WinPEAS vBETA VERSION, Please if you find any issue let me know in https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/issues by carlospolop

  [+] Leyend:
         Red                Indicates a special privilege over an object or something is misconfigured
         Green              Indicates that some protection is enabled or something is well configured
         Cyan               Indicates active users
         Blue               Indicates disabled users
         LightYellow        Indicates links

   [?] You can find a Windows local PE Checklist here: https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation


  ========================================(Services Information)========================================

  [+] Interesting Services -non Microsoft-(T1007)
   [?] Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
    daclsvc(DACL Service)["C:\Program Files\DACL Service\daclservice.exe"] - Manual - Stopped
    YOU CAN MODIFY THIS SERVICE: WriteData/CreateFiles, AllAccess
    File Permissions: Administrators [AllAccess]
    Possible DLL Hijacking in binary folder: C:\Program Files\DACL Service (Administrators [AllAccess])
   =================================================================================================

    dllsvc(DLL Hijack Service)["C:\Program Files\DLL Hijack Service\dllhijackservice.exe"] - Manual - Stopped
    YOU CAN MODIFY THIS SERVICE: Start, AllAccess
    File Permissions: Administrators [AllAccess]
    Possible DLL Hijacking in binary folder: C:\Program Files\DLL Hijack Service (Administrators [AllAccess])
   =================================================================================================

    filepermsvc(File Permissions Service)["C:\Program Files\File Permissions Service\filepermservice.exe"] - Manual - Stopped
    YOU CAN MODIFY THIS SERVICE: Start, AllAccess
    File Permissions: Everyone [AllAccess], Administrators [AllAccess]
    Possible DLL Hijacking in binary folder: C:\Program Files\File Permissions Service (Administrators [AllAccess])
   =================================================================================================

    regsvc(Insecure Registry Service)["C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"] - Manual - Stopped
    YOU CAN MODIFY THIS SERVICE: Start, AllAccess
    File Permissions: Administrators [AllAccess]
    Possible DLL Hijacking in binary folder: C:\Program Files\Insecure Registry Service (Administrators [AllAccess])
   =================================================================================================

    ssh-agent(OpenSSH Authentication Agent)[C:\Windows\System32\OpenSSH\ssh-agent.exe] - Disabled - Stopped
    YOU CAN MODIFY THIS SERVICE: Start, AllAccess
    Possible DLL Hijacking in binary folder: C:\Windows\System32\OpenSSH (Administrators [WriteData/CreateFiles])
    Agent to hold private keys used for public key authentication.
   =================================================================================================

    unquotedsvc(Unquoted Path Service)[C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe] - Manual - Stopped - No quotes and Space detected
    YOU CAN MODIFY THIS SERVICE: Start, AllAccess
    File Permissions: Administrators [AllAccess]
    Possible DLL Hijacking in binary folder: C:\Program Files\Unquoted Path Service\Common Files (Administrators [AllAccess])
   =================================================================================================

    VBoxService(Oracle and/or its affiliates - VirtualBox Guest Additions Service)[C:\Windows\System32\VBoxService.exe] - Auto - Running
    YOU CAN MODIFY THIS SERVICE: AllAccess
    File Permissions: Administrators [AllAccess]
    Possible DLL Hijacking in binary folder: C:\Windows\System32 (Administrators [WriteData/CreateFiles])
    Manages VM runtime information, time synchronization, remote sysprep execution and miscellaneous utilities for guest operating systems.
   =================================================================================================


  [+] Modifiable Services(T1007)
   [?] Check if you can modify any service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
    LOOKS LIKE YOU CAN MODIFY SOME SERVICE/s:
    AJRouter: AllAccess
    ALG: AllAccess
    AppIDSvc: AllAccess
    Appinfo: Start, AllAccess
    AppReadiness: AllAccess
    AudioEndpointBuilder: AllAccess
    Audiosrv: AllAccess
    autotimesvc: AllAccess
    AxInstSV: AllAccess
    BDESVC: Start, TakeOwnership
    BFE: TakeOwnership
    BITS: AllAccess
    BrokerInfrastructure: TakeOwnership, Start
    Browser: AllAccess
    BTAGService: AllAccess
    BthAvctpSvc: AllAccess
    bthserv: AllAccess
    camsvc: AllAccess
    CDPSvc: AllAccess
    CertPropSvc: WriteData/CreateFiles
    ClipSVC: Start, TakeOwnership
    COMSysApp: AllAccess
    CryptSvc: AllAccess
    daclsvc: WriteData/CreateFiles, AllAccess
    DcomLaunch: TakeOwnership
    dcsvc: AllAccess
    defragsvc: AllAccess
    DeviceAssociationService: AllAccess
    DeviceInstall: AllAccess
    DevQueryBroker: AllAccess
    Dhcp: Start, AllAccess
    diagnosticshub.standardcollector.service: AllAccess
    diagsvc: AllAccess
    DiagTrack: AllAccess
    DispBrokerDesktopSvc: AllAccess
    DisplayEnhancementService: Start, AllAccess
    dllsvc: Start, AllAccess
    DmEnrollmentSvc: AllAccess
    dmwappushservice: Start, AllAccess
    ...
```
#### Verify w/ `accesschk.exe`
[AccessChk.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) is a SysInternals tool. If we find a service that we can modify, we can confirm this with `accesschk.exe`. The following output is an example for `daclsvc` for the `user` user and the `admin` user on a Windows 10 machine:
```ps
PS C:\Users\admin> .\accesschk.exe /accepteula -uwcqv user daclsvc
RW daclsvc
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_CHANGE_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_START
        SERVICE_STOP
        READ_CONTROL
PS C:\Users\admin> .\accesschk.exe /accepteula -uwcqv admin daclsvc
RW daclsvc
        SERVICE_ALL_ACCESS
```


> [!Resources]
> - [AccessChk.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) 