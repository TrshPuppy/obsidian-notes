
# Handling Users in Linux

## Adding Users:
To add a user to a linux system use the `adduser` command followed by the name of the user. `adduser` will prompt you to also create a password for the new user, and will probably also create a new group for the user.

The new user will also get a home directory in `/home/newuser`, and will be listed in the `/etc/passwd` file:
```bash
sudo adduser newuser
[sudo] password for trshpuppy:
Adding user `newuser' ...
Adding new group `newuser' (1001) ...
Adding new user `newuser' (1001) with group `newuser' ...
Creating home directory `/home/newuser' ...
Copying files from `/etc/skel' ...
New password:
Retype new password:
passwd: password updated successfully
Changing the user information for newuser
Enter the new value, or press ENTER for the default
        Full Name []: new user
        Room Number []:
        Work Phone []:
        Home Phone []:
        Other []:
Is the information correct? [Y/n] y
```
```bash
# the 'su' command lets us switch to the new user:
su newuser
Password:
newuser@trshheap:~$ # <-- new user shell context
cat /etc/passwd | grep "newuser"
newuser:x:1001:1001:new user,,,:/home/newuser:/bin/bash
```

## /etc/passwd
This file doesn't actually have passwords stored in it, but used to. Now, it can concatenated to see information about users on the machine.
```bash
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```
The `x` in the second field is a placeholder for the user's password. The following field is the "user ID". In the `root` user's line, the user ID is `0` meaning `root` is the OG user.

Each line in the `/etc/passwd` file also lists the home folder and shell types of each user. For example the home folder for `root` user is `/root` and the shell type is bash (`/bin/bash`).

Different services running on the computer will likely be listed as users in `/etc/passwd`, which means that concatenating it can tell you what services and programs are present.

## /etc/shadow
To view the `/etc/shadow` folder you need super user permissions. This file *contains hashed passwords* for users on the system:
```bash
sudo cat /etc/shadow
[sudo] password for trshpuppy:
root:*:18375:0:99999:7:::
daemon:*:18375:0:99999:7:::
...
newuser:$6$oi/lTewmOz8/mkiA$sysDHsD(...).:19496:0:99999:7:::
```

The fields listed for each user breakdown as follows:
```bash
mark:$6$.n.:17736:0:99999:7:::
[--] [----] [---] - [---] ----
|      |      |   |   |   |||+-----------> 9. Unused (reservered)
|      |      |   |   |   ||+------------> 8. Expiration date
|      |      |   |   |   |+-------------> 7. Inactivity period
|      |      |   |   |   +--------------> 6. Warning period
|      |      |   |   +------------------> 5. Maximum password age
|      |      |   +----------------------> 4. Minimum password age
|      |      +--------------------------> 3. Last password change
|      +---------------------------------> 2. Encrypted Password
+----------------------------------------> 1. Username
```
-[Linuxize: Understanding the /etc/shadow File](https://linuxize.com/post/etc-shadow-file/)

### Encrypted Password:
The encrypted password field is formatted as: `$type$salt$hash` where `$type` is the encryption algorithm used. The following algorithms can be used:
- `$1$`: MD5
- `$2a$`: Blowfish
- `$2y$`: Eksblowfish
- `$5$`: SHA-256
- `$6$`: SHA-512

>	*Note:* In Linux, since the passwords are both hashed *and salted* the same password will result in two different hashes. *This is not true for Windows* where the same password for two different users will result in the exact same hash.

If the password field is set to `!` of `*` that means the user will not be able to use password authentication to login (other methods like `su` and key-based auth are still allowed).

For best practice users like `root` should not be able to login with a password. Instead, root access can be controlled by allowing some users to temporarily elevate their permissions to root, and logging to keep records of when that has happened.

## Groups
### /etc/group
The `/etc/group` file lists all the groups on the machine and which users are in them. Each line in the file has 4 fields:
```bash
sudo:x:27:trshpuppy,newuser
[--][-][-][----------------]
  |  |  |         |+ ---------> Group List: users in the group (separated w/ ',')
  |  |  |+--------------------> Group ID: ea user has a group ID (listed in                   
  |  |                          /etc/passwd)
  |  |+-----------------------> Password: Not generally used, 'x' placeholder
  |+--------------------------> Group Name: name of the group
```
-[CyberCiti: Understanding /etc/group File](https://www.cyberciti.biz/faq/understanding-etcgroup-file/)

### /etc/sudoers
The `/etc/sudoers` file contains information on the sudoers group including which users are part of it and who can use `sudo` to escalate their privileges.
```bash
sudo cat sudoers
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root    ALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "#include" directives:

#includedir /etc/sudoers.d
```

When investigating a box/ system it's good to know what the sudo privileges are. You can do that by using `sudo -l`:
```bash
sudo -l
Matching Defaults entries for trshpuppy on trshheap:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User trshpuppy may run the following commands on trshheap:
    (ALL : ALL) ALL
```
In this example, the `sudo` command and users in the sudoers group have `ALL` permissions.

Man entry for `sudo -l`:
```
 -l, --list:
If no command is specified, list the allowed (and forbidden) commands for the invoking user (or the user specified by the -U option) on the current host.  A longer list format is used if this option is specified multiple times and the security policy supports a verbose output format.

If a command is specified and is permitted by the security policy, the fully-qualified path to the command is displayed along with any command line arguments.  If a command is specified but not allowed by the policy, sudo will exit with a status value of 1.
```

> [!Resources:]
> - [Linuxize: Understanding the /etc/shadow File](https://linuxize.com/post/etc-shadow-file/)
> - [CyberCiti: Understanding /etc/group File](https://www.cyberciti.biz/faq/understanding-etcgroup-file/)

