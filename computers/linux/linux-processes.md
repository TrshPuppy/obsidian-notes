
# Linux Processes
The programs running on the machine. Managed by the kernel which gives each process a PID. The PID *increments for the order of which the process was started* (60th process PID = 60).
## How do Processes Start:
### Namespaces:
Namespaces are how the operating system splits up available resources and isolates them. Processes within the same namespace will have access to a delegated amount of computing power which is small compared to what is available overall.

Namespaces are *more secure* because they isolate processes from one another. Only processes w/i the same namespace can "see" each other.
### init
`init` is `pid 1` in linux and refers to the *kernel*. Everything coming after `init` is *a child process of `init`*. To change values for the `init` process/ `pid 1` you can use [`gdb`](/computers/linux/gdb.md) (GNU Project Debugger)
### systemd
`systemd` is a service manager for Linux OS's. When it is started on boot as the first process (PID 1) it acts as an *initialization system* which brings up and maintains userspace services.

`systemd` is the system's init process and sits in between the operating system and the user.

Any program that we want to start on boot will likely start as a *child process* of `systemd`, which means `systemd` controls it. The child processes of `systemd` will share the same resources as it, but will still run as their own process.
#### Configuration:
When `systemd` is ran as a *system instance* it interprets the configuration file `system.conf` and files in `system.conf.d` directories.

When ran as a *user instance*, `systemd` interprets the configuration file `user.conf` and the files in `user.conf.d`.
#### Units:
`systemd` provides a dependency system between 11 different entities called *"units"*. These units encapsulate various objects which are necessary for system boot-up and maintenance.

Most of the 11 units are configured and set up via configuration files, but some are created from other configuration, dynamically from system state, or programmatically at runtime.

Units can be active, inactive, activating (b/w inactive and active), deactivating (vice versa), or a special state of *failed* (entered when the service failed in some way).

`systemd` only keeps a minimal number of units loaded into memory. Any unit that does *NOT* have the *inactive* state is kept in memory (active, activating, deactivating, failed). Units will only be kept loaded in memory if *one of the following is true*:
1. state = active, activating, deactivating, or failed
2. the unit has a job queued for it
3. the unit is a *dependency* of at least one other unit that *is currently also loaded into memory*
4. it still has a form of resource allocated to it (like a service unit who's state is inactive but still has a process lingering which ignored the termination request)
5. it has been pinned into memory programmatically via a *"D-Bus call."*

*Currently loaded units are invisible to the client* (can use `systemctl list-units --all` to list all currently-loaded units).
##### List of units:
Units are named for their configuration files. Some have special semantics (see `systemd.special(7)`):
1. Service Units: start and control daemons and processes they consist of (`systemd.service(5)`)
2. Socket units: encapsulate local IPC or network sockets, useful for socket-based activation (see `systemd.socket(5)` & `daemon(7)`)
3. Target units: group units or provide synchronization-points during boot-up (`systemd.target(5)`)
4. Device units: expose kernel devices and can be used for device-based activation (`systemd.device(5)`)
5. Mount units: control mount points in the file system (`systemd.mount(5)`)
6. Automount units: for on-demand mounting of file systems and parallelized boot-up (`systemd.automount(5)`)
7. Timer units: for triggering activation of other units based on timers (`systemd.timer(5)`)
8. Swap units: encapsulate memory swap partitions or OS files (`systemd.swap(5)`)
9. Path units: activates other services when file system objects are changed or modified (`systemd.path(5)`)
10. Slice units: group units which manage system processes in hierarchical tree (`systemd.slice(5)`)
11. Scope units: manage foreign processes instead of starting them as well (`systemd.scope(5)`)
### Starting processes w/ `systemctl`:
Processes told to start on boot are usually critical and configured by an administrator.
#### systemctl
`systemctl` is a command/ service which allows you to interact with the `systemd` process/ daemon.
```bash
systemctl [options] [service]
```

There are four options which can be given to `systemctl`:
1. start: start one or more units (must already be loaded in memory)
2. stop: deactivate one or more units
3. enable: enable one or more units/ unit instances. Creates a set of *"symlinks"* as encoded in the "[Install]" section of the indicated unit files.
4. disable: disables one or more units and removes all symlinks to the unit files from the unit configuration directory.
5. 
##### `systemctl enable` (start on boot)
To [start a process on boot](https://tryhackme.com/room/linuxfundamentalspart3#) use: `systemctl enable <target service>`.
## Viewing Processes:
The `ps` command will list all of the running processes on the current user's session, plus additional information like the status code, usage time, CPU usage, and the name or the program or command being executed.

To see processes run by other users and/or *system processes* use the switch `aux` with the `ps` command:
```shell
 ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.5 102672 11116 ?        Ss   00:20   0:04 /sbin/init
root           2  0.0  0.0      0     0 ?        S    00:20   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   00:20   0:00 [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   00:20   0:00 [rcu_par_gp]
root           5  0.0  0.0      0     0 ?        I<   00:20   0:00 [netns]
root           7  0.0  0.0      0     0 ?        I<   00:20   0:00 [kworker/0:0H
root           9  0.0  0.0      0     0 ?        I<   00:20   0:00 [kworker/0:1H
root          10  0.0  0.0      0     0 ?        I<   00:20   0:00 [mm_percpu_wq
root          11  0.0  0.0      0     0 ?        S    00:20   0:00 [rcu_tasks_ru
root          12  0.0  0.0      0     0 ?        S    00:20   0:00 [rcu_tasks_tr
root          13  0.0  0.0      0     0 ?        S    00:20   0:00 [ksoftirqd/0]
root          14  0.0  0.0      0     0 ?        I    00:20   0:00 [rcu_sched]
root          15  0.0  0.0      0     0 ?        S    00:20   0:00 [migration/0]
root          16  0.0  0.0      0     0 ?        S    00:20   0:00 [idle_inject/
root          18  0.0  0.0      0     0 ?        S    00:20   0:00 [cpuhp/0]
...
```

The `top` command will give you *real-time stats* on the running processes that updates q 10 seconds, or whenever you navigate through them with the arrow keys:
```shell
top - 01:32:58 up  1:12,  1 user,  load average: 0.00, 0.00, 0.00
Tasks:  99 total,   1 running,  98 sleeping,   0 stopped,   0 zombie
%Cpu(s):  0.0 us,  0.3 sy,  0.0 ni, 99.7 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
MiB Mem :   1972.7 total,   1140.6 free,    181.0 used,    651.1 buff/cache
MiB Swap:      0.0 total,      0.0 free,      0.0 used.   1634.3 avail Mem 

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND  
      1 root      20   0  102672  11116   8104 S   0.0   0.6   0:04.12 systemd  
      2 root      20   0       0      0      0 S   0.0   0.0   0:00.00 kthreadd 
      3 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 rcu_gp   
      4 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 rcu_par+ 
      5 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 netns    
      7 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 kworker+ 
      9 root       0 -20       0      0      0 I   0.0   0.0   0:00.13 kworker+ 
     10 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 mm_perc+ 
     11 root      20   0       0      0      0 S   0.0   0.0   0:00.00 rcu_tas+ 
     12 root      20   0       0      0      0 S   0.0   0.0   0:00.00 rcu_tas+ 
     13 root      20   0       0      0      0 S   0.0   0.0   0:00.08 ksoftir+ 
     14 root      20   0       0      0      0 I   0.0   0.0   0:00.56 rcu_sch+ 
     15 root      rt   0       0      0      0 S   0.0   0.0   0:00.02 migrati+ 
     ...
```
## Managing Processes:
You can send signals to terminate processes which change based on how cleanly you want the process to be killed.
### kill
the `kill` command takes the PID as an arg and kills a process outright. The kill command can also be given #signals to decide how the process is killed:
- `SIGTERM`: (-15) will give the process the chance to handle the signal internally (or ignore it)
	- `kill -15 <PID>`
- `SIGKILL`:(-9) kill the process outright
- `SIGINT`: (`^C`) In the terminal, when you stop a command by hitting `Ctrl C` you send a `SIGINT` signal to the command.
- `SIGSTP`:(`^Z`) Using `Ctrl Z` in the terminal will send a suspend signal, causing the currently running process to enter a state of suspension until an `fg` (foreground) command brings it back to the foreground.
### Exit Codes:
The exit code of the last terminated process can be accessed by typing `echo $?`, the variable which the exit code is saved in immediately after termination.
```bash
sleep 30 & ps
[1] 41506
    PID TTY          TIME CMD
   6790 pts/0    00:00:00 bash
  41506 pts/0    00:00:00 sleep
  41507 pts/0    00:00:00 ps
trshpuppy@trshpile:/etc$ kill -15 41506
trshpuppy@trshpile:/etc$ echo $?
0
[1]+  Terminated              sleep 30

```
### Backgrounding and Foregrounding
Processes can be run in either of two states: the background or the foreground.
#### Backgrounding:
```shell
# echo defaults to foreground:
echo "hello"
hello

# running echo in the background using '&':
echo "hello" &
[1] 1264
$ hello

[1]+  Done                    echo "hello"
# when ran in the background unsing '&' we are given the PID instead
```
*Using `Ctrl Z` also backgrounds and suspends a process* (`SIGSTP`)
#### Foregrounding:
When a process is backgrounded, use `fg` to bring it back to the foreground so the output of the script is returned in the terminal.
```shell
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
^Z
[1]+  Stopped                 python3 -m http.server
ps
    PID TTY          TIME CMD
   1007 pts/0    00:00:00 bash
   1286 pts/0    00:00:00 python3
   1290 pts/0    00:00:00 ps
fg 1286
-bash: fg: 1286: no such job
fg python3
python3 -m http.server
```
## Process Automation
### cron
`cron` is a process which is started on boot and can be interacted with via `crontab`. [crontab](/CLI-tools/linux/crontab.md) is responsible for facilitating and managing *cron jobs*.

A crontab is a special file with *formatting recognized by the `cron` process*. Crontabs require 6 specific values:

|value|description|
|-|-|
|MIN|What minute to execute at|
|HOUR| What hour to execute at|
|DOM|What day of the month to execute at|
|MON|What month of the year to execute at|
|DOW|What day of the week...|
|CMD|The actual command to execute|
grep through all cron jobs `/var/log/cron.log`
#### Example: backing up files:
If you wanted to backup files in `Documents` q12 hours:
```shell
0 */12 * * * cp -R /home/trshpuppy/Documents /var/backups/ >/dev/null 2>&1
```


> [!Resouces]
> - [THM Linux Fundamentals pt. 3](https://tryhackme.com/room/linuxfundamentalspart3)
> - [Linux Signals](https://www.howtogeek.com/devops/linux-signals-hacks-definition-and-more/)
> - [Crontab generator tool](https://crontab-generator.org/)

> [!Related]
> - Command line: [psypy](cybersecurity/tools/actions-on-objective/psypy.md)





