
# `searchsploit` CLI Tool:
Init.
## Usage
```bash
searchsploit
  Usage: searchsploit [options] term1 [term2] ... [termN]

==========
 Examples 
==========
  searchsploit afd windows local
  searchsploit -t oracle windows
  searchsploit -p 39446
  searchsploit linux kernel 3.2 --exclude="(PoC)|/dos/"
  searchsploit -s Apache Struts 2.0.0
  searchsploit linux reverse password
  searchsploit -j 55555 | jq
  searchsploit --cve 2021-44228

  For more examples, see the manual: https://www.exploit-db.com/searchsploit
```
  
> [!Resources]
> - `man searchsploit`

