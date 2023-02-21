
# MySQL UNION Attack:
When an attacker uses the #SQL `UNION` keyword to retrieve data from more than one table in the database.

## UNION keyword:
In SQL the `UNION` keyword allows you to execute more than one `SELECT` query and append the results to the original query.
- Removes duplicate rows as default

Example:
`SELECT a, b FROM table1 UNION SELECT c, d FROM table2`
- This query will return a single result with two columns, containing values from columns `a` and `b` in `table1` and `c` and `d` from `table2`.

## Attack requirements:
1. The # and order of columns which appear in all SELECT statements must be the same
2. The data types of the columns must be the same or compatible

Sample tables:
```sql
DROP TABLE IF EXISTS t1;
DROP TABLE IF EXISTS t2;

CREATE TABLE t1 (
    id INT PRIMARY KEY
);

CREATE TABLE t2 (
    id INT PRIMARY KEY
);

INSERT INTO t1 VALUES (1),(2),(3);
INSERT INTO t2 VALUES (2),(3),(4);
```

This statement combines result sets returned from `t1` and `t2`:
```sql
SELECT id
FROM t1
UNION
SELECT id
FROM t2;
```

Final result- contains values from separate result sets returned from the queries:
``` shell-session
+----+
| id |
+----+
|  1 |
|  2 |
|  3 |
|  4 |
+----+
4 rows in set (0.00 sec)
```

>[!Links]
> https://www.mysqltutorial.org/sql-union-mysql.aspx/
> https://portswigger.net/web-security/sql-injection/union-attacks

