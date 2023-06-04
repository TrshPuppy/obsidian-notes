# Gathering Breached Credentials
When large companies are hacked and their customer data is stolen, it's usually sold (usually on the dark web) amongst malicious actors. 

It's useful to have access to these large data dumps because the usernames/ passwords/ emails which make them up can be used to exploit targets in ethical hacking as well.

## Methodology:


## Breach Parse:
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


