
# Hydra
Hydra is a [brute forcing](/cybersecurity/TTPs/cracking/brute-force.md) tool used primarily for cracking passwords and logins on a network. It can brute force multiple connections/ login attempts *at the same time* which reduces the time it takes (when compared to sequential brute forcing).
## Use
### Installation
Hydra can be installed using apt:
```bash
apt install hydra
```
## Syntax
### Basic Syntax:
```bash
hydra -l <username> -p <password> <ip> <service> -o <file name>
```
### `-l` login:
Give hydra a list of usernames.
```bash
hydra -l molly -p butterfly 10.10.137.76 ssh
```
**Note:** You can leave the value blank w/ `''` if the username is not needed.
#### `-L` Login:
Supply the list using a text file. If you have a text file filled with a wordlist of possible usernames, you can supply it w/ `-L`.
`usernames.txt`:
```bash
root
admin
user
molly
steve
richard
```
```bash
hydra -L usernames.txt -p butterfly 10.10.137.76 ssh
```
### `-p` & `-P` password:
Similar to `-l`/ `-L` you can use the `-p` and `-P` flags to supply a password or text file of passwords for hydra to try:
```bash
hydra -l molly -P passwords.txt 10.10.
167.73 ssh
```
### `-f` fail/ force stop
This flag tells hydra to *stop brute forcing* when a successful match is found.
```bash
hydra -l molly -p butterfly -f 10.10.136.
98 ssh
```
### `-v` verbose
The `-v` flag will tell hydra to output its progress as it works.
### `-s` port number
The `-s` flag is used to tell hydra which port on the target IP to attack. If we want to attack port 6969 then our command looks like:
```bash
hydra  -l molly -p peanuts -f 10.10.10.136 ssh -s 6969
```
### The `<service>` field
This field takes the service you want hydra to brute force on the target IP. If you want to brute force an [SSH](/networking/protocols/SSH.md) login for example, you provide `ssh`.

#### `http` service
For an [HTTP](/networking/protocols/HTTP.md) brute force, you need to provide the URL *w/ a placeholder for where hydra should inject the credentials*. Additionally, the URL string will be divided into *3 parts by the `:` delimiter* like this:
```bash
hydra ... http-post-form "<URL endpoint>:<parameters to bruteforce>:<error string>"
```
- `<URL endpoint>` will be whatever page, appended to the IP where the login we're trying to brute force is. For example, if the login page is at `http://10.10.161.7/login.php` then `/login.php` goes here.
- `<parameters>` this will hold the parameters we're brute forcing such as username and password (which we supplied w/ the `-L` and `-P` flags). If there is more than one, then we separate them w/ the `&` like you would in an actual URL. So, brute forcing username and password will look like this: `hydra... http-post-form "...:username=^USER^&password=^PASS^"`
- `<error string>` In order for hydra to know when it's found a successful match, we need to give it a string which *appears in the HTML of the response when a login attempt has failed*. So, if a failed login attempt returns an error like "Login failed", then we put that in this field: `hydra... http-post-form "...:Login failed"`.

Putting these all together will look like this:
```bash
hydra -L usernames.txt -P passwords.txt -f -v 10.10.161.7 http-post-form "/login.php:password=^PASS^&username=^USER^:Login failed" -s 8000
```

> [!Resources]
> - [Try Hack Me Advent of Cyber '23](https://tryhackme.com/room/adventofcyber2023)
> - [Free Code Camp: Hydra](https://www.freecodecamp.org/news/how-to-use-hydra-pentesting-tutorial/)

