
# Detecting SQLi
Testing for [SQL-injection](../../TTPs/exploitation/injection/SQL-injection.md) should be done against *every input point* on an application/ website. W/ each attempt, look for *errors* or changes in how the application responds.
## Common Clauses
Most SQLis happen in the `WHERE` and `SELECT` clauses of SQL statements. However, they can also be accomplished with:
### `UPDATE`
Usually within the updated values of a `WHERE` clause.
### `INSERT`
W/i the inserted values.
### `SELECT`
Within a table or column name, or within an `ORDER BY` clause.
## Example Payloads
### `'`
Starting w/ a single quotation mark is good because it is very simple.
### Boolean Conditions
Such as `OR 1=2`, combined w/ the `'` to close off the input string and `--` to comment out the follow [SQL](../../../coding/languages/SQL.md) code.
### Time Delays
Payloads which trigger a time delay when executing the SQL query. Look for *differences in the time it takes* for the app to respond.
### OAST Payloads
OAST payloads are used to trigger out of band network interaction when executed in a SQL query. 

> [!Resources]
> - [Port Swigger Academy](https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-retrieving-hidden-data/sql-injection/retrieving-hidden-data)

