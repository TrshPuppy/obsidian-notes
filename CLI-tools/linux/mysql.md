
# `mysql` Command Line Utility
Used to authenticate to and interact with a MySQL or MariaDB instance. Ca
## Usage

### Authenticating
The following command will authenticate us w/ a username and password to a remote MySQL instance. Once we connect, we'll have a `mysql `shell which we can use to run commands and [SQL](../../coding/languages/SQL.md) queries.
```shell
trshpuppy@trshpile$ mysql -u root -p'root' -h 192.168.10.69 -P 3306
Enter password: <password>
...SNIP...

mysql>
```
#### `-u` flag
Used to supply the username. This is set to `root` in the example meaning you will log in as the 'root' user.
#### `-p` flag
Used to supply the password and should *never be followed by the password* b/c it will show in plaintext in the `bash_history` file (leaving it blank will cause it to prompt you afterward).
#####  `-h` and `-P` flags:
Specifies a remote host and port. If not set, it will default to localhost. Default port MySQL/ MariaDB port is port `3306`.
### `system_user()`
The `system_user()` function will list the current database user for the current session. It returns the username and hostname for the MySQL connection:
```mysql
MySQL [(none)]> select system_user();
+--------------------+
| system_user()      |
+--------------------+
| root@192.168.20.50 |
+--------------------+
1 row in set (0.104 sec)
```
Note that the `root` user in this output refers to the database's root user  *not the system's root user*. 
### `show databases`
This command will show all of the running databases in the MySQL session:
```sql
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| test               |
+--------------------+
5 rows in set (0.107 sec)
```
### Accessing Data
We can run SQL commands against the databases using the `mysql` utility:
```sql
MySQL [mysql]> SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';
+--------+------------------------------------------------------------------------+
| user   | authentication_string                                                  |
+--------+------------------------------------------------------------------------+
| offsec | $A$005$?qvorPp8#lTKH1j54xuw4C5VsXe5IAa1cFUYdQMiBxQVEzZG9XWd/e6|
+--------+------------------------------------------------------------------------+
1 row in set (0.106 sec)
```
In the output, you can see that the `offsec` user's password is saved (in the `authentication_string`) column as a *Caching-SHA-256* algorithm. 
### `information_schema`
`information_schema` is a *database within each MySQL instance* which holds *metadata* about the MySQL server. It can also be referred to as the "data dictionary" or "system catalog." In general, it gives information about the databases on the server, data types for each column in tables, access privileges, etc..
The tables in the `information_schema` database are *read only* and there are no actual files associated with them. So, you cannot use `INSERT`, `UPDATE`, or `DELETE` operations on it. You can only use the `USE` keyword to query it.
```sql
mysql> SELECT table_name, table_type, engine 
	FROM information_schema.tables 
	WHERE table_schema = 'db5' 
	ORDER BY table_name; 
	+------------+------------+--------+ 
	| table_name | table_type | engine | 
	+------------+------------+--------+ 
	| fk         | BASE TABLE | InnoDB | 
	| fk2        | BASE TABLE | InnoDB | 
	| goto       | BASE TABLE | MyISAM | 
	| into       | BASE TABLE | MyISAM | 
	| k          | BASE TABLE | MyISAM | 
	| kurs       | BASE TABLE | MyISAM | 
	| loop       | BASE TABLE | MyISAM | 
	| pk         | BASE TABLE | InnoDB | 
	| t          | BASE TABLE | MyISAM | 
	| t2         | BASE TABLE | MyISAM | 
	| t3         | BASE TABLE | MyISAM | 
	| t7         | BASE TABLE | MyISAM | 
	| tables     | BASE TABLE | MyISAM |
	| v          | VIEW       | NULL   | 
	| v2         | VIEW       | NULL   | 
	| v3         | VIEW       | NULL   | 
	| v56        | VIEW       | NULL   | 
	+------------+------------+--------+ 
	17 rows in set (0.01 sec)
```
### Creating a database
``` shell
mysql> CREATE DATABASE users;

Query OK, 1 row affected (0.02 sec)
```
MySQL expects queries to be terminated with a `;`.
The `USE` statement switches the `users` database.
**SQL commands are not case-sensitive, but the names of databases/ tables/ columns etc. are.**
### Tables
[DBMS](../../coding/databases/DBMS.md)s store data in tables. The intersection of a row and column is called a cell.
- tables are created w/ a fixed set of columns
- each column is a specific data type
#### Creating a table
``` shell
mysql> CREATE TABLE logins (
    ->     id INT,
    ->     username VARCHAR(100),
    ->     password VARCHAR(100),
    ->     date_of_joining DATETIME
    ->     );
Query OK, 0 rows affected (0.03 sec)
```
#### List all tables in a database
```shell
mysql> SHOW TABLES;

+-----------------+
| Tables_in_users |
+-----------------+
| logins          |
+-----------------+
1 row in set (0.00 sec)
```
#### Using a specific table
```bash
MariaDB [(none)]> use creds;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [creds]> show tables;
+-----------------+
| Tables_in_creds |
+-----------------+
| creds           |
+-----------------+
1 row in set (0.092 sec)

MariaDB [creds]>
```
#### Describe table in a database
```shell
mysql> DESCRIBE logins;

+-----------------+--------------+
| Field           | Type         |
+-----------------+--------------+
| id              | int          |
| username        | varchar(100) |
| password        | varchar(100) |
| date_of_joining | date         |
+-----------------+--------------+
4 rows in set (0.00 sec)
```


> [!Resources]
> - [Offsec](offsec.com)
> - [Invicti: SQLi Cheat Sheet](https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/#UnionInjections)