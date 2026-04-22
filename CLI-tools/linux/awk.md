# `awk` Cheat Sheet
### 1. Prepend or Append
For example, create a wordlist by taking a pre-existing wordlist, and then appending (or prepending) a word to the beginning of each word in the wordlist:
```bash
root# cat users.txt | awk '{print "CONTOSO\\"$1}' | head
CONTOSO\root
CONTOSO\admin
CONTOSO\test
CONTOSO\guest
CONTOSO\info
CONTOSO\adm
CONTOSO\mysql
CONTOSO\user
CONTOSO\administrator
CONTOSO\oracle
```
**NOTE:** Have to escape the `\` character with another `\` character.

> [!Resources]
> - [GNU: awk Manual](https://www.gnu.org/software/gawk/manual/html_node/Escape-Sequences.html)
