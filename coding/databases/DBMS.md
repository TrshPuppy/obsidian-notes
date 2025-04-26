---
aliases:
  - database
  - databases
---

# Database Management Systems
Create, define, host, and manage databases.
## Essential Features:
### Concurrency
When multiple users are interacting with the DB simultaneously, the DBMS makes sure the [concurrency](../concepts/coroutines.md#Concurrency%20vs%20Parallelism) interactions succeed and not cause data to be corrupted or lost.
### Consistency
With increased concurrent interactions, the data needs to remain consistent and valid throughout the database.
### Security
Provides "fine-grained" user authentication and permissions to prevent unauthorized viewing or changing of data.
## Architecture
Two tiered structure:
![](/coding/coding-pics/DBMS-1.png)
-[Hack the Box](https://academy.hackthebox.com/module/33/section/178)
### Tier 1
Client side applications/ websites/ GUIs. Handles user interaction like logging in, commenting, etc.. Data is usually passed to Tier 2 through API calls.
### Tier 2
Usually referred to as "middleware," Tier 2 interprets events from Tier 1 and formats them for the DBMS. This tier exists in the [application layer](../../networking/OSI/7-application/application-layer.md) and uses different libraries, drivers, etc. to interact with the DB. The database receives queries from Tier 2 and performs the requested operations which could be  insertion, retrieval, deletion, or updating of data, etc.. Data is processed and returned (or an error is returned if the query is invalid)

It's usually best practice to host DB and application server *separately*, however increased data, users, queries etc. can cause decreased performance.
## Types of Databases
### Relational Databases
![My notes on RDBMS](RDBMS.md)
#### Relational Database Languages
##### SQL
[SQL](/coding/languages/SQL.md) 
##### MySQL
[mysql](mysql.md)
### Non-Relational Databases
Non relational databases do not use tables, rows, columns, keys, relationships, or schemas. Instead, data is stored in various storage models r/t the type of data being stored. B/c they have less structure, NoSQL databases are more scalable and flexible than RDBMSs.
#### Common storage models:
##### 1. key-value DB
Usually uses [JSON](../data-structures/JSON.md) or XML.
##### 2. Document-based
##### 3. Wide-Column
##### 4. Graph

#### Languages
[MongoDB](coding/databases/MongoDB.md) is the most common type of NoSQL database.

> [!Resources]
> - [Hack the Box](https://academy.hackthebox.com/module/33/section/178)
