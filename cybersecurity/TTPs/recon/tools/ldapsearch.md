
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