
# MSSQL
A [DBMS](../../coding/databases/DBMS.md) which works natively w/ Windows. The built-in command line tool for working with MSSQL is `SQLCMD`.  `SQLCMD` allows [SQL](../../coding/languages/SQL.md) queries to be ran through Windows Command prompt or *remotely from another device.*
## TDS
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
## Other Tidbits
### [`xp_cmdshell`](../../OSCP/Web%20Apps/SQLi.md#In%20MSSQL)
![My notes on `xp_cmdshell` - OSCP notes](../../OSCP/Web%20Apps/SQLi.md#In%20MSSQL)

> [!Resources]
> - [Offsec](offsec.com)

> [!Related]
> - [`mssqlclient.py`](../../cybersecurity/TTPs/exploitation/tools/impacket.md#`mssqlclient.py`) Impacket tool