
Init.
# `ldapsearch` Command

```bash
┌──(hakcypuppy㉿kali)-[~]
└─$ ldapsearch -h > ld
ldapsearch: option requires an argument -- 'h'
ldapsearch: unrecognized option -h
usage: ldapsearch [options] [filter [attributes...]]
where:
  filter        RFC 4515 compliant LDAP search filter
  attributes    whitespace-separated list of attribute descriptions
    which may include:
      1.1   no attributes
      *     all user attributes
      +     all operational attributes
Search options:
  -a deref   one of never (default), always, search, or find
  -A         retrieve attribute names only (no values)
  -b basedn  base dn for search
  -c         continuous operation mode (do not stop on errors)
  -E [!]<ext>[=<extparam>] search extensions (! indicates criticality)
             [!]accountUsability         (NetScape Account usability)
             [!]domainScope              (domain scope)
             !dontUseCopy                (Don't Use Copy)
             [!]mv=<filter>              (RFC 3876 matched values filter)
             [!]pr=<size>[/prompt|noprompt] (RFC 2696 paged results/prompt)
             [!]ps=<changetypes>/<changesonly>/<echg> (draft persistent search)
...
```
> from `ldapsearch -h`
## Use
### Example Syntax
```bash
ldapsearch -D 'guest' -b 'DC=EGOTISTICAL-BANK,DC=LOCAL' -H ldap://egotistical-bank.local:389
```
## Other Tips
### Unauthenticated Checks
#### Dump of all Objects
```bash
ldapsearch -LLL -x -H ldap://<domain fqdn> -b '' -s base '(objectclass=*)'
```
### Authenticated Checks
#### Extract all User Objects
```bash
ldapsearch -x -h <IP Address> -D '<domain>\<username>' -w '<password>' -b "CN=Users,DC=<domain>,DC=<domain>"
```
#### Extract all Computer Objects
```bash
```ldapsearch -x -h <IP Address> -D '<domain>\<username>' -w '<password>' -b "CN=Computers,DC=<domain>,DC=<domain>"
```
#### Extract all Domain Admins
```bash
ldapsearch -x -h <IP Address> -D '<domain>\<username>' -w '<password>' -b "CN=Domain Admins,CN=Users,DC=<domain>,DC=<domain>"
```

> [!Resources]
> - [curtishoughton: Pentesting Cheat Sheet - LDAP](https://github.com/curtishoughton/Penetration-Testing-Cheat-Sheet/blob/master/Enumeration/LDAP/LDAP.md)
