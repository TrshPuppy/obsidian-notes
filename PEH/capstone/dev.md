
# Dev Walkthrough
Treat these boxes as if they were CTFs (and not like actual pentests).
# My Attack Vector
## 1. Nmap Recon
```bash
sudo nmap -Pn -p- $t
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-09 13:15 EDT
Nmap scan report for 10.0.2.7
Host is up (0.00028s latency).
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
8080/tcp  open  http-proxy
36593/tcp open  unknown
36953/tcp open  unknown
39333/tcp open  unknown
51501/tcp open  unknown
MAC Address: 08:00:27:75:18:29 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 6.66 seconds
```
## 2. Port 80 & 8080
### 80 [HTTP](networking/protocols/HTTP.md)
![](nested-repos/PNPT-study-guide/PNPT-pics/dev-1.png)
![](/PNPT-pics/dev-1.png)
#### Findings:
Default page for Bolt CMS
### Port 8080
![](nested-repos/PNPT-study-guide/PNPT-pics/dev-2.png)
![](/PNPT-pics/dev-2.png)
#### Findings:
`phpinfo()` page which proves [PHP](coding/languages/PHP.md) is *being executed at this endpoint*. `phpinfo()` itself also gives up a *lot of information about the target*:
- *PHP Version*: 7.3.27-1
- *System*: Linux dev 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64
- *Apache Version*: 2.4.38 (Debian)
- *Mysql:*
	- Version: 5.0.12
	- Plugins: mysqlnd, debug_trace,  auth_plugin_mysql_native_password, auth_plugin_mysql_clear_password, auth_plugin_sha256_password
- *OpenSSL Version*: 1.1.1d
- *SQLite3 Version*: 3.27.2
- Etc.
## 3. Port 2049: [NFS](computers/linux/NFS.md)
Network Filesystem (a Linux service for hosing filesystem shares and allowing remote/ in-network devices to access them *via mounting*).
### Findings:
#### `showmount`
`showmount` command used on the target shows a share mounted at `/srv/nfs`.
#### `mount`
Using the `mount` command, we can mount the remote target share to our own filesystem, and find this:
```bash
┌──(hakcypuppy㉿kali)-[~/dev]
└─$ sudo mount -t nfs4 10.0.2.7:/srv/nfs ~/

┌──(hakcypuppy㉿kali)-[~/dev]
└─$ ls ~/
save.zip   # <----- from the target mount share
```
### Unzipping `save.zip`
Using `unzip` against `save.zip`, we discover the zipped file is password protected:
```bash
unzip save.zip
Archive:  save.zip
[save.zip] id_rsa password:
```
#### [zip2john](cybersecurity/tools/cracking/john.md)
Using `zip2john` on the zip file, we're able to crack the password:
```bash
zip2john save.zip
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 6 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
Proceeding with incremental:ASCII
java101          (save.zip)        # <-----------
1g 0:00:00:03 DONE 3/3 (2023-10-09 14:45) 0.2923g/s 9806Kp/s 9806Kc/s 9806KC/s bbs1700..javona1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
#### Using the password
Now, if we use the password cracked by john (`java101`), we can try `unzip` again:
```bash
unzip save.zip
Archive:  save.zip
[save.zip] id_rsa password: java101  # <-------------
```
Two files are deflated from the zipped file: `id_rsa` and `todo.txt`.
### `todo.txt`
Starting w/ this file, let's `cat` the contents:
```bash
cat todo.txt                                                                    
- Figure out how to install the main website properly, the config file seems correct...
- Update development website
- Keep coding in Java because it's awesome

jp
```
From this file we learn:
1. the main website is not installed properly (probably why we see a Bolt default page when we visit `http://10.0.2.7:80`)
2. There is a config file somewhere
3. There is a development website (which needs updating)
4. JP thinks *java is awesome*
## 4. [Feroxbuster](cybersecurity/tools/scanning-enumeration/feroxbuster.md)
### Port 80
Let's find some endpoints using feroxbuster:
```bash
feroxbuster -u http://10.0.2.7:80
200      GET      107l      370w     3833c http://10.0.2.7/
301      GET        9l       28w      302c http://10.0.2.7/app => http://10.0.2.7/app/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://10.0.2.7/app (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://10.0.2.7/app/config (Apache)
200      GET       19l       82w      633c http://10.0.2.7/app/nut
MSG      0.000 feroxbuster::heuristics detected directory listing: http://10.0.2.7/app/cache (Apache)
301      GET        9l       28w      305c http://10.0.2.7/public => http://10.0.2.7/public/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://10.0.2.7/app/database (Apache)
200      GET       26l       81w      672c http://10.0.2.7/app/config/menu.yml
200      GET      121l      356w     3498c http://10.0.2.7/app/config/routing.yml
200      GET       26l       93w      793c http://10.0.2.7/app/config/taxonomy.yml
200      GET      187l     1302w     8519c http://10.0.2.7/app/config/permissions.yml
200      GET      353l     1439w    12219c http://10.0.2.7/app/config/contenttypes.yml
MSG      0.000 feroxbuster::heuristics detected directory...
```
There are a lot of findings, but some especially tasty ones are:
#### http://10.0.2.7/app
![](nested-repos/PNPT-study-guide/PNPT-pics/dev-3.png)
![](/PNPT-pics/dev-3.png)
At this endpoint we find an entire directory listing. There is many a tasty morsel along these paths, but here are some especially good ones:
##### /app/config/config.yml
This endpoint has *plaintext credentials* seemingly for an [SQL](coding/languages/SQL.md) database:
```yaml
# Database setup. The driver can be either 'sqlite', 'mysql' or 'postgres'.
#
# For SQLite, only the databasename is required. However, MySQL and PostgreSQL
# also require 'username', 'password', and optionally 'host' ( and 'port' ) if the database
# server is not on the same host as the web server.
#
# If you're trying out Bolt, just keep it set to SQLite for now.
database:
    driver: sqlite
    databasename: bolt
    username: bolt
    password: I_love_java

# The name of the...
```
###### Other /config morsels:
- `/config/permissions.yml`: outlines how permissions for different users are handled and *what types of users exist* (including admin and guest accounts)
- `config/routing.yml`: outlines how other endpoints are routed including an endpoint *which takes POST requests* (potential file uploads?)
##### /app/cache/config-cache.json
*More plaintext credentials* as well as some other information revealing more about the app/ website's structure:
```json
 "general": {
        "database": {
            "driver": "pdo_sqlite",
            "host": "localhost",
            "slaves": [],
            "dbname": "bolt",
            "prefix": "bolt_",
            "charset": "utf8",
            "collate": "utf8_unicode_ci",
            "randomfunction": "RANDOM()",
            "databasename": "bolt",
            "username": "bolt",
            "password": "I_love_java",
            "user": "bolt",
            "wrapperClass": "Bolt\\Storage\\Database\\Connection",
            "path": "/var/www/html/app/database/bolt.db"
        },
        "sitename": "A sample site",
        "locale": "en_G...
```
##### /app/database
This leads directly to a bolt database at `/app/database/bolt.db`, but unfortunately there is no data saved there.
##### /app/nut
This is a PHP script which reveals more about the infrastructure:
```php
#!/usr/bin/env php
<?php
/*
 * This could be loaded on a very old version of PHP so no syntax/methods over 5.2 in this file.
 */

$minVersion = '5.5.9';
if (version_compare(PHP_VERSION, $minVersion, '<')) {
    echo sprintf("\033[37;41mBolt requires PHP \033[1m%s\033[22m or higher. You have PHP \033[1m%s\033[22m, so Bolt will not run on your current setup.\033[39;49m%s", $minVersion, PHP_VERSION, PHP_EOL);
    exit(1);
}

/** @var \Silex\Application $app */
$app = require __DIR__ . '/bootstrap.php';
$app->boot();

/** @var \Symfony\Component\Console\Application $nut Nut Console Application */
$nut = $app['nut'];
$nut->run();
```
#### Other notes:
There are many `/vendor` endpoints/ directories but they don't seem very fruitful. There is also a number of `/public` endpoints but most of them don't resolve to anything useful.
### Port 8080
This Ferox output is much shorter:
```bash
http://10.0.2.7:8080/dev => http://10.0.2.7:8080/dev/
http://10.0.2.7:8080/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://10.0.2.7:8080/dev/config (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://10.0.2.7:8080/dev/pages (Apache)
http://10.0.2.7:8080/dev/pages => http://10.0.2.7:8080/dev/pages/
http://10.0.2.7:8080/dev/pages/member.admin
http://10.0.2.7:8080/dev/forms => http://10.0.2.7:8080/dev/forms/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://10.0.2.7:8080/dev/forms (Apache)
http://10.0.2.7:8080/dev/forms/form.admin
MSG      0.000 feroxbuster::heuristics detected directory listing: http://10.0.2.7:8080/dev/files (Apache)
http://10.0.2.7:8080/dev/config => http://10.0.2.7:8080/dev/config/
http://10.0.2.7:8080/dev/pages/site.linkrot
http://10.0.2.7:8080/dev/pages/member.thisisatest
http://10.0.2.7:8080/dev/forms/form.2dn22appu5qsjap74t64i689j3
http://10.0.2.7:8080/dev/forms/form.thisisatest
http://10.0.2.7:8080/dev/files => http://10.0.2.7:8080/dev/files/
http://10.0.2.7:8080/dev/stamps => http://10.0.2.7:8080/dev/stamps/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://10.0.2.7:8080/dev/stamps (Apache)
```
#### /dev
This brings us to a Bolt dashboard:
![](nested-repos/PNPT-study-guide/PNPT-pics/dev-4%201.png)
![](/PNPT-pics/dev-4.png)
From here there are some tabs we can peruse including `Admin`, `Register`, and `Setup`. We will come back to this.
##### /dev/config
This brings us to another directory listing similar to `:80/app` but this time it's not as deep:
![](nested-repos/PNPT-study-guide/PNPT-pics/dev-5.png)
![](/PNPT-pics/dev-5.png)
## 5. 8080 Dashboard
Coming back to the dashboard we discovered at `http://10.0.2.7:8080/dev`, let's see what we can do from here.
### Dead Ends:
The `Admin` and `Setup` tabs are dead ends. But, looking at the address bar after navigating to them, we can see some PHP parameters:
```
10.0.2.7:8080/dev/index.php?p=site.setup
```
This is from navigating to via the `Register` tab/button. 

From this string, we can tell that the script here `index.php` has some parameters which seem to have something to do with our routing. If we click the `Admin` tab, our search bar is filled w/ something similar:
```
http://10.0.2.7:8080/dev/index.php?p=site
```
And if we go to the `Welcome` tab, we get:
```
http://10.0.2.7:8080/dev/index.php?p=welcome
```
From these three URLs, we can tell that the parameter `p` in this script has something to do with our routing/ address.
### Register
If we go to the `Register` tab our URL changes slightly, revealing more about the underlying `index.php` script:
```
http://10.0.2.7:8080/dev/index.php?p=action.register
```
![](nested-repos/PNPT-study-guide/PNPT-pics/dev-6.png)
![](/PNPT-pics/dev-6.png)
Now we can see that the `p` parameter can be set to an action, such as `register`. Let's try `action.login`:
![](nested-repos/PNPT-study-guide/PNPT-pics/dev-7.png)
![](/PNPT-pics/dev-7.png)
Just by changing the action, we've rendered an entirely new page.

Since we're being given the option to register, let's see if we gain more access by doing so.
![](nested-repos/PNPT-study-guide/PNPT-pics/dev-8.png)
![](/PNPT-pics/dev-8.png)
Nothing much has changed, except that we're 'logged in'. Maybe there are some other actions we can take advantage of in the URL?