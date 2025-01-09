
# mysql Command Line Utility:
Used to authenticate to and interact with a MySQL or MariaDB database.
## Usage
```shell
trshpuppy@trshpile$ mysql -U root -p
Enter password: <password>
...SNIP...

mysql>
```
### Flags
#### `-U` flag:
> used to supply the username. This is set to `root` in the example meaning you will log in as the superuser.
#### `-p` flag:
> used to supply the password and ==should never be followed by the password b/c it will show in plaintext in the `bash_history` file== (leaving it blank will cause it to prompt you afterward).
#####  `-h` and `-P` flags:
> Specifies a remote host and port. If not set, it will ==default to the #Localhost==. Default port MySQL/ MariaDB port is #port-3306
> `mysql -U root -h docker.hackthebox.eu -P 3306 -p`
### Creating a database
``` shell
mysql> CREATE DATABASE users;

Query OK, 1 row affected (0.02 sec)
```
> MySQL expects queries to be terminated with a `;`.
### View a list of databases
```shell
mysql> SHOW DATABASES;

+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| users              |
+--------------------+

mysql> USE users;

Database changed
```
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