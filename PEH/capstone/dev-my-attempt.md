
# Dev Attempt
Treat these boxes as if they were CTFs (and not like actual pentests).
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
Default page for Bolt CMS.
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
Network Filesystem (a Linux service for hosting filesystem shares and allowing remote/ in-network devices to access them *via mounting*).
### Findings:
#### `showmount`
`showmount` command used on the target shows a share mounted at `/srv/nfs`.
#### `mount`
Using the `mount` command, we can mount the remote target share to our own filesystem, and find this:
```bash
┌──(hakcypuppy㉿kali)-[~/dev]
└─$ sudo mount -t nfs4 10.0.2.7:/srv/nfs /tmp/mount

┌──(hakcypuppy㉿kali)-[~/dev]
└─$ ls /tmp/mount
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
1. The main website is not installed properly (probably why we see a Bolt default page when we visit `http://10.0.2.7:80`)
2. There is a config file somewhere
3. There is a development website (which needs updating)
4. JP thinks *java is awesome*
## 4. [Feroxbuster](cybersecurity/tools/scanning-enumeration/dir-and-subdomain/feroxbuster.md)
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
![](nested-repos/PNPT-study-guide/PNPT-pics/dev-9.png)
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
### Bolt Documentation
Something is going on here that we can take advantage of, so let's look at the [Bolt Docs](https://docs.boltcms.io) to try to figure out what.
#### Bolt + Apache
We don't have to browse for very long before we find their [docs](https://docs.boltcms.io/5.0/installation/webserver/apache) r/t Apache (our target's webserver). Right away, we see a paragraph r/t *routing requests to `index.php`* which sounds a lot like what we've been encountering in the dashboard.

It says Bolt needs *an `.htaccess` file* in order to do the routing. A `.htaccess` file is a configuration file for directories on a webserver. It helps configures things like website-access, URL redirection, URL shortening, and access control. The docs say the file should look like this:
```.htaccess
# Use the front controller as index file. It serves as a fallback solution when
# every other rewrite/redirect fails (e.g. in an aliased environment without
# mod_rewrite). Additionally, this reduces the matching process for the
# start page (path "/") because otherwise Apache will apply the rewriting rules
# to each configured DirectoryIndex file (e.g. index.php, index.html, index.pl).
DirectoryIndex index.php

# By default, Apache does not evaluate symbolic links if you did not enable this
# feature in your server configuration. Uncomment the following line if you
# install assets as symlinks or if you experience problems related to symlinks
# when compiling LESS/Sass/CoffeScript assets.
# Options +FollowSymlinks

# Disabling MultiViews prevents unwanted negotiation, e.g. "/index" should not resolve
# to the front controller "/index.php" but be rewritten to "/index.php/index".
<IfModule mod_negotiation.c>
    Options -MultiViews
</IfModule>

<IfModule mod_rewrite.c>
    RewriteEngine On

    # Determine the RewriteBase automatically and set it as environment variable.
    # If you are using Apache aliases to do mass virtual hosting or installed the
    # project in a subdirectory, the base path will be prepended to allow proper
    # resolution of the index.php file and to redirect to the correct URI. It will
    # work in environments without path prefix as well, providing a safe, one-size
    # fits all solution. But as you do not need it in this case, you can comment
    # the following 2 lines to eliminate the overhead.
    RewriteCond %{REQUEST_URI}::$0 ^(/.+)/(.*)::\2$
    RewriteRule .* - [E=BASE:%1]

    # Sets the HTTP_AUTHORIZATION header removed by Apache
    RewriteCond %{HTTP:Authorization} .+
    RewriteRule ^ - [E=HTTP_AUTHORIZATION:%0]

    # Redirect to URI without front controller to prevent duplicate content
    # (with and without `/index.php`). Only do this redirect on the initial
    # rewrite by Apache and not on subsequent cycles. Otherwise we would get an
    # endless redirect loop (request -> rewrite to front controller ->
    # redirect -> request -> ...).
    # So in case you get a "too many redirects" error or you always get redirected
    # to the start page because your Apache does not expose the REDIRECT_STATUS
    # environment variable, you have 2 choices:
    # - disable this feature by commenting the following 2 lines or
    # - use Apache >= 2.3.9 and replace all L flags by END flags and remove the
    #   following RewriteCond (best solution)
    RewriteCond %{ENV:REDIRECT_STATUS} =""
    RewriteRule ^index\.php(?:/(.*)|$) %{ENV:BASE}/$1 [R=301,L]

    # If the requested filename exists, simply serve it.
    # We only want to let Apache serve files and not directories.
    # Rewrite all other queries to the front controller.
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^ %{ENV:BASE}/index.php [L]
</IfModule>

<IfModule !mod_rewrite.c>
    <IfModule mod_alias.c>
        # When mod_rewrite is not available, we instruct a temporary redirect of
        # the start page to the front controller explicitly so that the website
        # and the generated links can still be used.
        RedirectMatch 307 ^/$ /index.php/
        # RedirectTemp cannot be used instead
    </IfModule>
</IfModule>
```
Since this file handles access and configuration, let's see if we can find it.
![](nested-repos/PNPT-study-guide/PNPT-pics/dev-10.png)
![](/PNPT-pics/dev-10.png)

Looks like we can't directly access it, but the error here *suggests we found the right path.*
## 6. Circling back to Port 80
We're going down rabbit holes, so let's go back and look over our clues. At `http://10.0.2.7/` we have our Bolt page. If we *look closer* we can see that it's telling us "You've probably installed bolt in the wrong folder" and "the current folder is: `/var/www/html`".
### Document Root
It goes on to say that the easiest way to fix this is to *"configure the webserver to use `/var/www/html/public`"*. So, we've already learned: where this page is coming from, that it represents *the current document root for the server* and that it should be one dir deeper in a directory called "`public`".

If we try to access `/public` with the browser we find nothing, except that our browser URL changes to `http://10.0.2.7/public/bolt/userfirst`. There is nothing else here for now, so let's go back to the default Bolt page.

At the bottom of this page, there are links to "Troubleshooting 'Outside of the web root'". Let's click it.... it goes no where, so let's search it ourselves.

We find the Bolt CMS troubleshooting page for this issue [here](https://docs.boltcms.io/3.7/howto/troubleshooting-outside-webroot), and right away we get info on how the app is meant to be structured:
![](nested-repos/PNPT-study-guide/PNPT-pics/dev-13.png)
![](/PNPT-pics/dev-13.png)

The paths that get us things (but not super tasty things) are:
- 10.0.2.7/src
- /extensions
- /.bolt.yml
- /.htaccess
The paths which are tasty:
#### /.gitignore
```bash
# Don't put config.yml in git, unless you're absolutely sure that all sensitive
# info (database credentials, mail settings) are _only_ in config_local.yml
app/config/config.yml

# Usually we don't put 'uploaded files' into git either.
files/

# Modify this, only if you've changed the default folder in .bolt.yml
public/bolt-public/

# -----------------------------------------------------------------------------

# Config files with '_local' should *never* go into git
app/config/*_local.yml
app/config/extensions/*_local.yml

# SQLite databases should not go into git
app/database/

cache/
thumbs/
vendor/

# NPM, Gulp and Grunt stuff
node_modules
bower_components
npm-debug.log
.sass-cache

# File-system cruft and temporary files
*.gz
*.sublime-*
*.zip
.*.swp
._*
.buildpath
.DS_Store
.idea/
.vscode
.project
.swp
.Trashes
.vagrant*
/bolt.log
/tags
__*
php-cs-fixer.phar
scrutinizer.phar
composer.phar
Thumbs.db
Vagrantfile
```
From here we learn:
1. [Vagrant]() is involved some how which hints @ virtualization
	- However `/Vagrantfile` is a dead end
2. our composer file is called `composer.phar`
	- `/composer.phar` is a dead end
3. There is a database called `Thumbs.db`
	- dead end
4. There's a swap file/ image: `.swp`
	- dead end
Even though the endpoints aren't reachable right now, we've learned *a lot more about the structure of this site/ app* and the technologies it uses.
#### /composer.json
*We've found our Composer file!*:
```json
{
    "name": "bolt/composer-install",
    "description": "Sophisticated, lightweight & simple CMS",
    "type": "project",
    "license": "MIT",
    "require": {
        "php": "^5.5.9 || ^7.0",
        "bolt/bolt": "^3.7",
        "passwordlib/passwordlib": "^1.0@beta",
        "bolt/configuration-notices": "^1.0"
    },
    "minimum-stability": "beta",
    "prefer-stable": true,    
    "scripts": {
        "post-install-cmd": [
            "Bolt\\Composer\\ScriptHandler::installAssets"
        ],
        "post-update-cmd": [
            "Bolt\\Composer\\ScriptHandler::updateProject",
            "Bolt\\Composer\\ScriptHandler::installAssets"
        ],
        "post-create-project-cmd": [
            "Bolt\\Composer\\ScriptHandler::configureProject",
            "Bolt\\Composer\\ScriptHandler::installThemesAndFiles",
            "nut extensions:setup"
        ]
    },
    "autoload": {
        "psr-4": {
            "Bundle\\": "src/"
        }
    }
}
```
This gives us even more information including *the versioning for composer as well as bolt*. There is also a `composer.lock` file, but it's much larger, so let's just download it for now just in case.

## 7. Findings so far...
Let's go over our findings and decide on a next move. 
### Prioritizing
Starting with the ports we scanned, which one seems the most vulnerable right now? 
#### 80 & 8080
... are probably the most vulnerable *since we know for a fact that the website is not configured correctly.* Additionally, we have an endpoint which is executing PHP (`:8080/`), and some versioning info for web services the site uses including Apache, Bolt, and PHP.
#### 2049/ BFS
Next, we have the NFS (port 2049). Even though we were able to mount the one share on the target, and crack the zip file there, this port is less vulnerable *since we have no indication that there are other shares we haven't found yet*. Additionally, can we be sure we could get access or execution if we mounted a directory to the target with a script in it? No.
#### SSH
Last we have SSH. We do have some credentials we could try on SSH, but that's about it right now.
### Credentials
We know from the note in the zip file that there may be a user called "JP". We've also got two passwords: 'java101' (which unzipped `save.zip`) and 'I_love_java' (which is meant for a user called "bolt" for an sqlite database, we found this in the `config.yml` file)
## Exploring 80 & 8080
Since Ports 80 & 8080 seem the most vulnerable, let's explore some exploits for them using the versions of the services we enumerated.
### Searchsploit
- `searchsploit apache 2 | grep linux`: there aren't many tasty exploits for Linux.
- `searchsploit php | grep linux`: lots of results, but none that are very tasty.
#### `searchsploit Bolt`
This search returns a few results. We're looking for Bolt v3.7 and there is one which looks promising:
![](nested-repos/PNPT-study-guide/PNPT-pics/dev-14.png)
![](/PNPT-pics/dev-14.png)

Finding this exploit on [Exploit DB](https://www.exploit-db.com/exploits/48296) we can peruse the code, written in [python](coding/languages/python/python.md). It appears that if you're authenticated to BoltCMS, you're able to take advantage of their routing system to achieve RCE via an injection into a URL containing `/files/test{}.php?test=<injection>`.

We *have a user which we registered* so let's attempt this while authenticated as that user:
![](nested-repos/PNPT-study-guide/PNPT-pics/dev-15.png)
![](/PNPT-pics/dev-15.png)

**BOOM** using the hints from the exploit DB script, we've discovered we can leverage the PHP parameters to traverse and see the filesystem. From here we can see all the user and the groups they're in.

At the bottom of the list is `jeanpaul` who is likely "jp" from `note.txt`
## Jeanpaul
Now that we know his username, let's try SSH again. And this time, let's use the password we found for the SQL database in `config.yml`. Since we know that JP loves Java, there is a chance that the password `I_love_java` is his!
### SSH
```bash
ssh jeanpaul@10.0.2.7
jeanpaul@10.0.2.7's password: I_love_java
Permission denied, please try again.
...
```
Unfortunately, it doesn't work, but there is one more thing we can try. We still have the `id_rsa` file we found in `save.zip`. We can set it as our private key for this SSH connection with `i` flag:
```
ssh -i id_rsa jeanpaul@10.0.2.7
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0744 for 'id_rsa' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "id_rsa": bad permissions
jeanpaul@10.0.2.7's password: 
Permission denied, please try again.
```
This time we're told our `id_rsa` file has bad permissions. SSH is gonna want us to to set it w/ a permission of 400 for read only. Let's use `chmod` to do that and try again:
```bash
> chmod 400 id_rsa
> ls -l id_rsa
-r-------- 1 hakcypuppy hakcypuppy   1876 Jun  2  2021 id_rsa
> ssh -i id_rsa jeanpaul@10.0.2.7
Enter passphrase for key 'id_rsa': java101 # <-- password on zip file (fails)
Enter passphrase for key 'id_rsa': I_love_java # <-- password for db (works!)
Linux dev 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Oct  9 17:39:34 2023 from 10.0.2.4
jeanpaul@dev:~$         # <---------------------------- WE'RE IN!
```

And this is as far as I got...

> [!Resources]
> -  [Bolt Docs](https://docs.boltcms.io)
> -  [Bolt Docs: Apache](https://docs.boltcms.io/5.0/installation/webserver/apache)
> - [BoltCMS: Troubleshooting WebRoot](https://docs.boltcms.io/3.7/howto/troubleshooting-outside-webroot)
> -  [Exploit DB: ID 48296](https://www.exploit-db.com/exploits/48296)

> [!My previous notes (linked in text)]
> - You'll find them all [here](https://github.com/TrshPuppy/obsidian-notes)
