# Blind SQL Injection
SQLi where the results are returned back to you are called "in-band." Conversely, SQLi where the results are *not* returned back to you are called "blind." Because the results aren't returned, you have to infer the outcome, usually via boolean or time-based logic.
## Boolean Based SQLi
Boolean based SQLi causes the application to return differing and predictable values when the query returns a `TRUE` or `FALSE` result. The results returned back to you *are usually from the web application* and not the actual database.
### Example
Let's say we have a web application hosted using [PHP](../../../coding/languages/PHP.md), and we notice in the address bar it has a `user` parameter:
```
http://vulnerable.com/dashboard.php?user=trshpuppy
```
When you're logged in as the user `trshpuppy` this is the url when you visit your dashboard. We can check for blind SQLi here with a boolean-based check like this:
```sql
http://vulnerable.com/dashboard.php?user=trshpuppy' AND 1=1 -- //
```
If the user `trshpuppy` is true, then the whole query with the injection should resolve as true. So, when we append our injected `AND` statement, the same content should appear on the page as when we don't append it. Using this boolean-based attack, we can enumerate the entire database for existing usernames.
## Time Based SQLi
In time based blind SQLi, an attacker uses differences in *response time* to conclude if an attempted query is `TRUE` or `FALSE`.
### Example
If we're looking at the same web application as the example above (boolean based section), then we can use a time based technique to check for SQLi by adding an `IF` condition:
```sql
http://vulnerable.com/dashboard.php?user=trshpuppy' AND IF (1=1, sleep(3), 'false') -- //
```
In [SQL](../../../coding/languages/SQL.md) the `IF()` function checks the first parameter (`1=1`), and if it's true it will sleep for 3 seconds (`sleep(3)`), and if it's false, it will return `false`. Since `1=1` is true, we expect the application to sleep for 3 seconds. However *that will only happen if the user `trshpuppy` is also true*.

So, time based blind SQLi can also be used for enumeration. If the user is false (doesn't exist), the application should immediately error (or do whatever behavior we observed it doing for usernames which don't exist). If the user is true (does exist), then the application should time-out for 3 seconds before returning any content.

> [!Resources]
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.
