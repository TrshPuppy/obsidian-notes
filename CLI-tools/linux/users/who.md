
# Who command
> The `who` command is provided by the GNU coreutils package, and its primary job is to parse the `/var/log/utmp` file and report its findings.
> 
> The `utmp` file logs the current users on the system. It doesn’t necessarily show every process, because not all programs initiate `utmp` logging. In fact, your system may not even have a `utmp` file by default. In that case, `who` falls back upon `/var/log/wtmp`, which records all logins and logouts.
> 
> The `wtmp` file format is exactly the same as `utmp`, except that a null user name indicates a logout and the `~` character indicates a system shutdown or reboot. The `wtmp` file is maintained by `login(1)`, `init(1)`, and some versions of `getty(8)`, however, none of these applications _creates_ the file, so if you remove `wtmp`, then record-keeping is deactivated. That alone is good to know: if `wtmp` is missing, you should find out why!


> [!Resources]
> - [RedHat](https://www.redhat.com/sysadmin/monitor-users-linux)