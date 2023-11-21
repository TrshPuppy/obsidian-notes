---
aliases: [DBMS, database-management-systems]
---
# Database Management Systems
Create, define, host, and manage databases.

## Essential Features:
Concurrency:
> When multiple users are interacting with the DB simultaneously, #DBMS makes sure the concurrent interactions succeed and not cause data to be corrupted or lost.

Consistency:
> W/ increased concurrent interactions, the data needs to remain consistent and valid throughout the database

Security:
> Provides "fine-grained" user authentication and permissions to prevent unauthorized viewing or changing of data.

## Architecture:
Two tiered structure:
![](/coding/coding-pics/DBMS-1.png)
-[Hack the Box](https://academy.hackthebox.com/module/33/section/178)
- ==Tier 1:==
	- Client side applications/ websites/ GUIs.
		- User interaction like logging in/ commenting, etc.
	- Data is passed to Tier 2 through #API calls
- ==Tier 2:==
	- #middleware
	- interprets events from Tier 1 and formats them for the DBMS
	- #application-layer uses different libraries, drivers, etc to interact with the DB
	- DB receives #queries from Tier 2 and performs requested operations.
		- insertion, retrieval, deletion, updating, etc.
		- data is processed and returned (or an error is returned if the query is invalid)
- ==Better to host DB and host separately==
	- increased data, users, queries etc ==> decreased performance.

## Types of Databases:
### Relational Databases:
#RDBMS are the most common type of databases.
- uses a #schema /template to dictate the structure/ how the data is stored in the DB.
	- Associated with #keys which provide access to a specific row or column.
	- tables or #entities are all related to each other
		- a change in one will effect others but only in a predictable way
![](/coding/coding-pics/DBMS-2.png)
-Hack the Box
Image:
> the `id` related to users in the `users` table is the same as `user_id` used to relate to user posts in the `posts` table. This type of relationship is more efficient because, for example, not all data related to each user has to be stored with their posts.

#### Languages:
[SQL](/coding/languages/SQL.md) 
[mysql](mysql.md)

### Non-Relational Databases:
Also called #NoSQL, does not use tables, rows, columns, keys, relationships, or schemas.
- Data is stored in various storage models r/t the type of data being stored
- B/c they have less structure, NoSQL databases are ==more scalable and flexible== than RDBMSs
- 4 common storage models:
	1. #key-value-DB
		- usually uses #JSON or #XML 
	2. #document-based-DB
	3. #wide-column-DB
	4. #graph-DB

#### Languages:
[MongoDB](coding/databases/MongoDB.md) is the most common type of NoSQL database.