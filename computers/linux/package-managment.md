
# Linux Package Management
## apt
Because Linux is open source, developers can submit software to an *apt* repository. If the software is approved, it then can be accessed by anyone using Linux via the CLI etc.

In `/etc/apt` the files listed with `ls` serve as the gateway/ registry (when on an Ubuntu machine):
```shell
ls
apt.conf.d  auth.conf.d  preferences.d  sources.list  sources.list.d  trusted.gpg.d
```

To see all of the repositories added to your source list
```shell
cat sources.list
## Note, this file is written by cloud-init on first boot of an instance
## modifications made here will not survive a re-bundle.
## if you wish to make changes you can:
## a.) add 'apt_preserve_sources_list: true' to /etc/cloud/cloud.cfg
##     or do the same in user-data
## b.) add sources in /etc/apt/sources.list.d
## c.) make changes to template file /etc/cloud/templates/sources.list.tmpl

# See http://help.ubuntu.com/community/UpgradeNotes for how to upgrade to
# newer versions of the distribution.
deb http://eu-west-1.ec2.archive.ubuntu.com/ubuntu/ focal main restricted
# deb-src http://eu-west-1.ec2.archive.ubuntu.com/ubuntu/ focal main restricted

## Major bug fix updates produced after the final release of the
## distribution.
deb http://eu-west-1.ec2.archive.ubuntu.com/ubuntu/ focal-updates main restricted
# deb-src http://eu-west-1.ec2.archive.ubuntu.com/ubuntu/ focal-updates main restricted
...
```
### Adding repos
`add-apt-repository` lets you add provider repos to your `sources.list`. Adding  repos to apt means that whenever we update our system the repos we add *are checked for updates*.
#### Software Integrity
To help ensure the integrity of software installed, apt uses *GPG (Gnu Privacy Guard) keys*. If the keys of the software do not match the public key provided by the software developers, then the software will not be downloaded.
##### Example with Sublime Text
1. Download the GPG key for the developers of Sublime Text
```shell
# from Sublime Text Apr '23:
wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/sublimehq-archive.gpg > /dev/null                                                                    
```
This downloads Sublime's PGP key and adds it to our `trusted.gpg.d` directory.

2. Add Sublime Text's repo to our apt sources list: *it's good practice to have a separate file for every repo you add.*
```shell
cd /etc/appt/sources.list.d
sudo nano sublime-text.list
```
GNU nano:
```nano
deb https://download.sublimetext.com/ apt/stable
```

3. Update apt so it recognizes the new entry with `apt update`
4. Install the software we have trusted and added to apt with `apt install sublime-text`
### Updating
The commands `apt update` updates the local package index with the latest information about available packages and their versions from the repositories defined in your system's sources list. It doesn't install or upgrade any packages; it just refreshes the information.
### Upgrading
The command `apt upgrade` upgrades all installed packages to their latest available versions based on the updated package index. It installs the new versions of the packages, but it won't remove any packages or install new ones that weren't previously installed.
### Removing Repos
You can remove  repos by either using this command:
```shell
add-apt-repository --remove ppa:<PPA_NAME>/ppa
``` 
Or by doing it manually by deleting the file.

Once removed, ask apt to remove the software:
```shell
apt remove [software name]
# sublime text example:
apt remove sublime-text
```
## Packages
### Listing packages
```bash
dpkg -l
```
### Purging packages
```bash
┌──(hakcypuppy㉿kali)-[~/blue]
└─$ dpkg -l | grep microsoft 
iU  microsoft-edge-stable                          117.0.2045.55-1                      amd64        The web browser from Microsoft

┌──(hakcypuppy㉿kali)-[~/blue]
└─$ dpkg --purge microsoft-edge-stable # <-------- HERE
dpkg: error: requested operation requires superuser privilege
┌──(hakcypuppy㉿kali)-[~/blue]
└─$ sudo !!   
sudo dpkg --purge microsoft-edge-stable 
(Reading database ... 471035 files and directories currently installed.)
Removing microsoft-edge-stable (117.0.2045.55-1) ...
Purging configuration files for microsoft-edge-stable (117.0.2045.55-1) ...
Processing triggers for man-db (2.11.2-3) ...
Processing triggers for kali-menu (2023.4.5) ...
Processing triggers for desktop-file-utils (0.26-1) ...
Processing triggers for mailcap (3.70+nmu1) ...
```

> [!Resources]
> - [THM Linux Fundamentals](https://tryhackme.com/room/linuxfundamentalspart3#)
> - `man apt`
> - `man dpkg`

