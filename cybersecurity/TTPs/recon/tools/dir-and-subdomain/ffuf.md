fuff
# Ffuf (Fuzz Faster U Fool)
Ffuf is a CLI tool used for [directory-enumeration](/cybersecurity/TTPs/recon/directory-enumeration.md). It is *non-recursive*, and will only enumerate at the specified depth in the command.
## Usage:
```bash
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://10.0.2.15/FUZZ
```
In this command the `FUZZ` keyword is used twice; once to tell us how to use the wordlist, and twice to *tell fuff where in the provided URL path it should enumerate.* So, fuff will only be enumerating results at the `FUFF` placeholder in the `-u` URL
### Useful Options
You can give fuff a set of guidelines for the enumeration, including what response status you want returned, whether it should follow redirects, etc..
```bash
ffuf -w wordlist.txt -u 'https://ffuf.io.fi/FUZZ' -mc all -fc 400
```
In this example, fuff will filter out all 400 (bad request) responses.
## Examples which worked
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt \
-u [https://domain.com/FUZZ](https://domain.com/FUZZ) \
-e .7z,.action,.ashx,.asp,.aspx,.backup,.bak,.bz,.c,.cgi,.conf,.config,.dat,.db,.dhtml,.do,.doc,.docm,.docx,.dot,.dotm,.git,.go,.htm,.html,.ini,.jar,.java,.js,.js.map,.json,.jsp,.jsp.source,.jspx,.jsx,.log,.md,.old,.pdb,.pdf,.php,.php2,.php3,.php4,.php5,.php6,.php7,.php8,.phtm,.phtml,.pl,.py,.pyc,.pyz,.rar,.rhtml,.shtm,.shtml,.sql,.sqlite3,.svc,.sh,.tar,.tar.bz2,.tar.gz,.tsx,.txt,.wsdl,.xhtm,.xhtml,.xls,.xlsm,.xlst,.xlsx,.xltm,.xml,.zip \
-t 30 -c \
-H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' \
-mc 200,204,301,307,401,403,500,302 \
-ic -o ffuf-clientname.txt \
-recursion 
```
#### With `uff`
```bash
# WORKED
uff -w wordlisttest \
-t 5 -c \
-u "https://198.135.80.42:443/FUZZ" \
-H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0'
```
#### With json output
```bash 
uff -w /opt/tools/wordlists/SecLists/Discovery/Web-Content/raft-large-directories-lowercase.txt \
-t 5 -e .7z,.asp,.aspx,.backup,.bak,.bz,.cgi,.conf,.config,.db,.doc,.docx,.git,.htm,.html,.ini,.jar,.js,.json,.jsp,.jspx,.jsx,.log,.md,.old,.pdf,.php,.py,.rar,.tar,.tar.bz2,.tar.gz,.sh,.txt,.xls,.xlsx,.xml,.zip \
-u https://tools.ciena.com/FUZZ \
-mc 200,204,301,307,401,403,500,302 \
-H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36' \
-ic \
-o ffuf-tools.json -of json
```

> [!Resources]
> - [FUFF GitHub Repo](https://github.com/ffuf/ffuf)

