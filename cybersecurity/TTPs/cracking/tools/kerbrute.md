
# `kerbrute` Command
## Use
### Syntax Example:
#### Userenum mode
Userenum mode does not attempt a login (so it won't lock actual users out). 
```
kerbrute userenum -d egotistical-bank --dc egotistical-bank.local -o users.txt
```
`-o` is a list of possible usernames
```bash
kerbrute userenum jsmith.txt -d domain.org -t 1 -v -o output.txt
```
`-t` is the time interval between requests (?)
#### Bruteforce mode
```bash
kerbrute bruteforce -d egotistical-bank --dc egotistical-bank.local users.txt
```
`users.txt` is a list of usernames matched with passwords like: `fsmith:password`


> [!Resources]
> - [GitHub](https://github.com/insidetrust/statistically-likely-usernames/tree/master)
