
# mysql Command Line Utility:
Used to authenticate to and interact with a #MySQL / #MariaDB database.

## Usage:
```shell-session
trshpuppy@trshpile$ mysql -U root -p
Enter password: <password>
...SNIP...

mysql>
```

The `-U` flag:
> used to supply the username. This is set to `root` in the example meaning you will log in as the superuser.

The `-p` flag:
> used to supply the password and ==should never be followed by the password b/c it will show in plaintext in the `bash_history` file== (leaving it blank will cause it to prompt you afterward).

The `-h` and `-P` flags:
> Specifies a remote host and port. If not set, it will ==default to the #Localhost==. Default port MySQL/ MariaDB port is #port-3306
> `mysql -U root -h docker.hackthebox.eu -P 3306 -p`

### Creating a database:
``` shell-session
mysql> CREATE DATABASE users;

Query OK, 1 row affected (0.02 sec)
```
> MySQL expects queries to be terminated with a `;`.

### View a list of databases:
```shell-session
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
> the `USE` statement switches the `users` database.

==SQL commands are not case-sensitive, but the names of databases/ tables/ columns etc. are.==
