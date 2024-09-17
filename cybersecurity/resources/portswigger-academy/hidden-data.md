
# Retrieving Hidden Data
A lot of web applications use a classic URL query syntax for querying SQL databases. For example, a website which sells cakes online might send a query using a URL like this (when a user clicks  on a `Cakes` button)
```url
https://cake-place.com/products?category=Cakes
```
Sending this query/ visiting this URL causes the application to *send a query to the SQL database* resembling something like:
```sql
SELECT * FROM products WHERE category = 'Cakes' AND released = 1
```
The query asks the database to return all details (`*`) from a table called `products` where the category is `Cakes` and the product has been released (`released = 1`/ the product is not hidden).
## Attack
If the application doesn't have any defenses against a SQLi attack, then an attacker can craft the following malicious URL query:
```url
https://cake-place.com/products?category=Cakes'+OR+1=1--
```
This results in the following SQL query being sent to the database:
```sql
`SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1`
```
This query will return *all of products in all categories* (not just the released ones) because:
- `OR 1=1` will cause the database to return products from the `Cakes` category or `TRUE` (so any category)
- `--` comments out the part of the SQL query we can't see which is `AND released = 1`, so the database won't apply that rule at all (meaning all products released and unreleased will be returned).