# Structured Query Language
A language created to manipulate data in a Relational Database Management System (RDBMS). Different RDBMSs may use different SQL syntax but they all must *follow the ISO standard for SQL*.
## Requirements
A SQL language must be able to:
- Retrieve data
- Update data
- Delete data
- Create new tables and databases
- Add and remove users
- Assign permissions to users
### Data definition
SQL handles the schema creation and modification of data. For example, the `CREATE TABLE` command creates a new table in a database. `ALTER TABLE` changes the structure of an existing table, etc..
### Data manipulation
SQL provides the interface/ constructs to query and update data including commands like ``SELECT``, ``INSERT``, ``UPDATE``, ``DELETE``, etc..
### Data control
SQL can handle *user authentication* and *authorization*. Two commands r/t to these are the `GRANT` and `REVOKE` keywords.
## Creating a table
``` sql
CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
    );
```
### Table Properties
With `CREATE TABLE` there are multiple *properties* which can be set for a table and each of its columns. For example, the `AUTO_INCREMENT` keyword can be set on `int` type columns (+1 every time a new item is added)
```sql
 id INT NOT NULL AUTO_INCREMENT,
```
`NOT NULL` will ensure that a column *is never left empty*
```sql
    username VARCHAR(100) UNIQUE NOT NULL,
```
`UNIQUE` ensures that every inserted item is unique
```sql
    date_of_joining DATETIME DEFAULT NOW(),
```
`DEFAULT` specifies the default value (in this example setting the default to `NOW()` will return the current date and time)
### Command Line
The [mysql](../../CLI-tools/linux/mysql.md) command line utility is used to authenticate to and interact with a MySQL or MariaDB database.
### SQL Standard
The first SQL-standard was implemented in 1986 to standardize use among vendors by the American Standards Institute (ANSI). The latest released standard is *SQL/2011*. Even though there are standards, *SQL dialects* have been created in their use spaces when consumers want features or capabilities which SQL doesn't yet have.

>[!Resources]
> - [SQL Tutorial](https://www.sqltutorial.org/)
> - [Hack the Box Academy, SQL Injection Module](https://academy.hackthebox.com/module/33/section/177)

> [!Related]
> - [SQLi](../../cybersecurity/TTPs/exploitation/injection/SQLi.md)
> - [mysql](../../CLI-tools/linux/mysql.md) command line tool
> - [MSSQL](../../CLI-tools/windows/MSSQL.md)
> - [UNION-attack](../../cybersecurity/TTPs/exploitation/injection/UNION-attack.md)