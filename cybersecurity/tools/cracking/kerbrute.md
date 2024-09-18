
# `kerbrute` Command
[GitHub link](https://github.com/ropnop/kerbrute/blob/master/session/session.go)
## Use
### Syntax Example
#### Userenum mode
`kerbrute userenum -d egotistical-bank --dc egotistical-bank.local users.txt`
 `users.txt` is a list of possible usernames
#### Bruteforce mode
`kerbrute bruteforce -d egotistical-bank --dc egotistical-bank.local users.txt`
`users.txt` is a list of usernames matched with passwords like: `fsmith:password`