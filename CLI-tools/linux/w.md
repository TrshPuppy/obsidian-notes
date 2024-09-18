
# `w` Command
Provides info on who is logged in including idle times, CPU time used by the processes attached to the [tty](../../../computers/linux/terminal-tty-shell.md) and the CPU time of the current process (under the `final` field).
```bash
$ w
 13:45:48 up 29 days, 19:24,  2 users,  load average: 0.53, 0.52, 0.54
USER     TTY     LOGIN@  IDLE    JCPU   PCPU WHAT
seth     tty2    Sun18   43:22m  0.01s  0.01s /usr/libexec/gnome-session-binary
curly    pts/2   13:02   35:12   0.03s  0.03s -bash
```
You can also *see the user's [IP address](../networking/IP-addresses.md)* by using the `-i` or `--ip-addr` flags.

> [!Resources]
> - [RedHat](https://www.redhat.com/sysadmin/monitor-users-linux)