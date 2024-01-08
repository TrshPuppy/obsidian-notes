
# dirb
dirb is a CLI tool used for [directory-enumeration](cybersecurity/TTPs/recon/directory-enumeration.md). It is *recursive* and will go through *every level* of a every directory found on a URL.
## Usage:
```bash
dirb http://10.0.2.15                                                                 
-----------------
DIRB v2.22    
By The Dark Raver
-----------------
START_TIME: Fri Oct  6 15:21:59 2023
URL_BASE: http://10.0.2.15/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
-----------------
GENERATED WORDS: 4612                                                          
---- Scanning URL: http://10.0.2.15/ ----
+ http://10.0.2.15/index.html (CODE:200|SIZE:10701)
==> DIRECTORY: http://10.0.2.15/phpmyadmin/                   
+ http://10.0.2.15/server-status (CODE:403|SIZE:274)
---- Entering directory: http://10.0.2.15/phpmyadmin/ ----
+ http://10.0.2.15/phpmyadmin/ChangeLog (CODE:200|SIZE:17598) 
...
```

> [!Resources]
> - `man dirb`
