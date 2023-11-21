---
aliases: [SQL, structured-query-language]
---
# Structured Query Language
A language created to manipulate data in a Relational Database Management System ( #RDBMS)
- Different RDBMSs may have different #SQL syntax but they ==all must follow the #ISO standard for SQL==
- Must be able to perform the following actions:
	- Retrieve data
	- Update data
	- Delete data
	- Create new tables and databases
	- Add/ remove users
	- Assign permissions to users

## The language:
The language is considered:
1. a data definition language:
	- handles the schema creation and modification
		- ex: ``CREATE TABLE`` creates a new table in the #database
		- ``ALTER TABLE`` changes the structure of an existing table
2. a data manipulation language:
	- provides the interface/constructs to query and update data
		- ex: ``SELECT``, ``INSERT``, ``UPDATE``, ``DELETE``, etc.
3. a data control language:
	- deals with user authentication/ authorization and security
		- ex: ``GRANT`` or ``REVOKE``

### Creating a table:
``` sql
CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
    );
```
##### Table Properties:
With `CREATE TABLE` there are multiple *properties* which can be set for a table and each of its columns:
*example:* `AUTO_INCREMENT` keyword can be set on int type columns (+1 every time a new item is added)
```sql
 id INT NOT NULL AUTO_INCREMENT,
```
> `NOT NULL` will ensure that a column ==is never left empty==

```sql
    username VARCHAR(100) UNIQUE NOT NULL,
```
> `UNIQUE` ensures that every inserted item is unique

```sql
    date_of_joining DATETIME DEFAULT NOW(),
```
> `DEFAULT` specifies the default value (in this example setting the default to `NOW()` will return the current date and time)
> 

### Command Line:
[mysql](mysql.md) is a command line utility used to authenticate to and interact with a #MySQL / #MariaDB database.

### SQL Standard:
- The first #SQL-standard was implemented in 1986 to standardize use among vendors
	- by the American Standards Institute ( #ANSI)
- Latest release standard = #SQL/2011
- Even though there are standards, #SQL-dialects have been created in their use spaces when consumers want features or capabilities which SQL doesn't yet have.

>[!links]
>https://www.sqltutorial.org/
>
>Hack the Box Academy, SQL Injection Module:
>https://academy.hackthebox.com/module/33/section/177

