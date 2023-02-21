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

### Command Line:
[[mysql]] is a command line utility used to authenticate to and interact with a #MySQL / #MariaDB database.


### SQL Standard:
- The first #SQL-standard was implemented in 1986 to standardize use among vendors
	- by the American Standards Institute ( #ANSI)
- Latest release standard = #SQL/2011
- Even though there are standards, #SQL-dialects have been created in their use spaces when consumers want features or capabilities which SQL doesn't yet have.


>[!links]
>https://www.sqltutorial.org/

