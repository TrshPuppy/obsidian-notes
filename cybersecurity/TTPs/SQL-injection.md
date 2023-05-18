---
aliases: [SQL-injection, SQLi]
---
# SQL Injection Attack (SQLi)
A vulnerability in web-security in which the queries sent by an application to its database are exploited by a threat actor.
- Usually for the purpose of viewing protected data.
- Data can be modified or deleted by the attacker which can effect the applications content and/or behavior.
- #SQLi can also be used to compromise the underlying server or back-end infrastructure, or perform a [denial-of-service](denial-of-service.md) attack.

## Examples of SQLi vulnerabilities/ techniques:
1. Modifying an SQL query to retrieve hidden data or additional results
2. Subverting the logic of the application by changing a query in a way that interfere's with the application's logic.
3. [UNION-attack](UNION-attack.md) where data can be retrieved from different database tables.
4. Extracting information about the database itself including its structure, version etc.
5. #blind-SQLi where the results of a query are not returned in the application's response.

## Attack-flow example (retrieving hidden data):
A shopping application displays data about products in different categories:
- when a user clicks on the "gifts" categories, their browser requests the URL ``https://insecure-website.com/products?category=Gifts``
	- The application makes an SQL query to its database to retrieve information of the relevant products:
		- ``SELECT * FROM products WHERE category = `Gifts` AND released = 1``
		- ``* `` asks for 'all details'
		- from the products table
		- where the category is Gifts
		- and released is 1 (hides products which are not released)
			- assume unreleased products = `0` 
- An attacker can construct an attack using a similar URL:
	- ``https://insecure-website.com/products?category=Gifts`--``
	- The #SQL-query would look like this: 
		- ``SELECT * FROM products WHERE category = `Gifts`--` AND released = 1``
	- the `--` is a comment indicator in SQL and would comment out the rest of the query.
		- This removes the rest of the query so that `AND released = 1` is no longer included
- An attacker can also construct a URL which will shows them all the products, including ones which are not meant to be seen:
	- new URL: ``https://insecure-website.com/products?category=Gifts`+OR+1=1--``
	- resulting query:
		- ``SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1``
		- This query returns all itemse where either the category is Gifts or 1 is equal to 1.
			- (since 1=1 is always true, the query returns ALL ITEMS)

>[!links]
> [Port Swigger](https://portswigger.net/web-security/sql-injection)
