
# Linux Processes
The programs running on the machine. Managed by the kernel which gives each #process a PID. The PID *increments for the order of which the process was started* (60th process PID = 60).

## How do Processes Start:
### Namespaces:
#Namespaces are how the operating system splits up available resources and isolates them. Processes within the same namespace will have access to a delegated amount of computing power which is small compared to what is available overall.

Namespaces are *more secure* because they isolate processes from one another. Only processes w/i the same namespace can "see" each other.

### systemd
When Ubuntu boots the first process to start (with a PID of 0) is *systemd*. #systemd is the systems init process and sits in between the operating system and the user.

Any program that we want to start on boot will likely start as a "child process" of systemd, which means systemd controls it. The child processes of systemd will share the same resources as it, but will still run as their own process.

### Starting processes on boot:


## Viewing Processes:
The `ps` command will list all of the running processes on the current user's session, plus additional information like the status code, usage time, CPU usage, and the name or the program or command being executed.

To see processes run by other users and/or *system processes* use the switch `aux` with the `ps` command:
```shell
tryhackme@linux3:~$ ps aux
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
trshpuppy@trshpile:/etc$ sleep 30 & ps
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



>[!links]
>[THM Linux Fundamentals pt. 3](https://tryhackme.com/room/linuxfundamentalspart3)
>[Linux Signals](https://www.howtogeek.com/devops/linux-signals-hacks-definition-and-more/)


