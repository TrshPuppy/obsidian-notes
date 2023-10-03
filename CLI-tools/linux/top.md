
# Top Command
Shows you the current processes running *in real time*:
```
Usage:
 top [options]

Options:
 -b, --batch-mode                run in non-interactive batch mode
 -c, --cmdline-toggle            reverse last remembered 'c' state
 -d, --delay =SECS [.TENTHS]     iterative delay as SECS [.TENTHS]
 -E, --scale-summary-mem =SCALE  set mem as: k,m,g,t,p,e for SCALE
 -e, --scale-task-mem =SCALE     set mem with: k,m,g,t,p for SCALE
 -H, --threads-show              show tasks plus all their threads
 -i, --idle-toggle               reverse last remembered 'i' state
 -n, --iterations =NUMBER        exit on maximum iterations NUMBER
 -O, --list-fields               output all field names, then exit
 -o, --sort-override =FIELD      force sorting on this named FIELD
 -p, --pid =PIDLIST              monitor only the tasks in PIDLIST
 -S, --accum-time-toggle         reverse last remembered 'S' state
 -s, --secure-mode               run with secure mode restrictions
 -U, --filter-any-user =USER     show only processes owned by USER
 -u, --filter-only-euser =USER   show only processes owned by USER
 -w, --width [=COLUMNS]          change print width [,use COLUMNS]
 -1, --single-cpu-toggle         reverse last remembered '1' state

 -h, --help                      display this help text, then exit
 -V, --version                   output version information & exit

For more details see top(1).
```
## Usage:
```bash
top
top - 09:48:15 up 4 days,  1:18,  2 users,  load average: 0.28, 0.24, 0.19
Tasks: 249 total,   1 running, 246 sleeping,   2 stopped,   0 zombie
%Cpu(s):  1.6 us,  2.5 sy,  0.0 ni, 95.9 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st 
MiB Mem :  31340.5 total,   4610.6 free,   5465.8 used,  21852.4 buff/cache     
MiB Swap:    975.0 total,    975.0 free,      0.0 used.  25874.7 avail Mem 

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND        
2419902 hakcypu+  20   0   12.0g 961152 307372 S  15.7   3.0 225:57.38 firefox-esr   
 199979 root      20   0 1993420   1.4g 147908 S   8.3   4.5 148:37.44 Xorg
```
### `load average` 
Over the last: 1 minute, 5 minutes, 15 minutes:
```bash
#                                                          1     5     15
top - 09:48:15 up 4 days,  1:18,  2 users,  load average: 0.28, 0.24, 0.19
```
Can use to troubleshoot issue w/ processes. Can also use to see if fixing something has helped (reflected in decreasing load averages since fix).
### CPU Processors
Hitting the 1 key shows you the processor cores (CPU) being used. If `wa` is > 0, then there are processes waiting on the core.
### Processes
For each process listed:
- `S` = sleeping 
- `R` = running
- `I`= idle
### `buff/cache` 
Linux uses free space as buffers/cache: this might be large.

> [!Resources]
> - `man top`