
# Breach-Parse
A [tool](https://github.com/hmaverickadams/breach-parse) written by Heath Adams which can search through large collections of breached data.
### Usage:
```bash
./breach-parse.sh @tesla.com tesla.txt
```
In this example, breach-parse will scan through `tesla.txt` and find all the usernames/ emails which include "tesla.com". Then it will return all the passwords associated with those accounts. 

The results are returned in 3 files:
- `tesla-master.txt`
- `tesla-passwords.txt`
- `tesla-users.txt`

> [!Resources]
> - [Heath Adams: Breach-Parse repo](https://github.com/hmaverickadams/breach-parse)

