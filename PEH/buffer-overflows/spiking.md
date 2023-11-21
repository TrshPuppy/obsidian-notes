
# Spiking w/ Vulnserver
The following notes were created while using [Vulnserver](https://thegreycorner.com/vulnserver.html) and [Immunity Debugger](https://www.immunityinc.com/products/debugger/) on a Windows 10 VM.
## Setup
Once Vulnserver and Immunity Debugger are installed on the vulnerable Windows VM, use `ipconfig` to find the VM's IP address. Verify your attack box and the vulnerable box can talk to each other (using [ping](CLI-tools/ping.md)).

Then you can connect to Vulnserver from your attack box using [netcat](cybersecurity/tools/netcat.md):
```bash
┌──(hakcypuppy㉿kali)-[~]
└─$ nc -nv $t 9999
(UNKNOWN) [10.0.2.15] 9999 (?) open
Welcome to Vulnerable Server! Enter HELP for help.
```
- `-n`: stands for numeric connections only (netcat will expect an IP address and port)
- `-v`: stands for verbose
- `9999` is the port Vulnserver will be listening on in the Windows box
### Commands
Now that you're connected, use `HELP` to get a list of commands:
```bash
┌──(hakcypuppy㉿kali)-[~]
└─$ nc -nv $t 9999
(UNKNOWN) [10.0.2.15] 9999 (?) open
Welcome to Vulnerable Server! Enter HELP for help.
HELP
Valid Commands:
HELP
STATS [stat_value]
RTIME [rtime_value]
LTIME [ltime_value]
SRUN [srun_value]
TRUN [trun_value]
GMON [gmon_value]
GDOG [gdog_value]
KSTET [kstet_value]
GTER [gter_value]
HTER [hter_value]
LTER [lter_value]
KSTAN [lstan_value]
EXIT
```
## Spiking Commands
Each of the listed commands can be *spiked* to find out whether they are vulnerable or not. To test each command, we can use `generic_send_tcp`, a command/ program on Kali:
```bash
┌──(hakcypuppy㉿kali)-[~]
└─$ generic_send_tcp
argc=1
Usage: ./generic_send_tcp host port spike_script SKIPVAR SKIPSTR
./generic_send_tcp 192.168.1.100 701 something.spk 0 0
```
### Targeting the `STATS` command
Starting with the `STATS` command, we need a spike script to supply to `generic...` to test it. All the script has to do is:
- be named w/ a `.spk` extension
- read a line
- create a string (in this case `"STATS"`)
- send a variable to the command (`STATS`)
```bash
#!stats.spk:
$_readline();
$_string("STATS");
$_string_variable("0"); # <--- variable to send
```
`generic_send_tcp` will take our script and use it to send strings of various lengths, all filled with "0", to the `STATS` command to *until the program breaks*.
#### Spiking:
With our script created, now we can send it to the program being hosted on Vulnserver using the `generic_tcp_send_tcp` command:
```bash
generic_send_tcp 10.0.2.15 9999 stats.spk 0 0
Total Number of Strings is 681
Fuzzing
Fuzzing Variable 0:0
Fuzzing Variable 0:1
Variablesize= 5004
Fuzzing Variable 0:2
Variablesize= 5005
...
Fuzzing Variable 0:436
Couldn't tcp connect to target
Variablesize= 1024
tried to send to a closed socket!
Fuzzing Variable 0:437
Couldn't tcp connect to target
^C   # <--- kill
```
In the output we can see that `generic_send_tcp` is sending variables of increasing sizes to the `STATS` command of the host. At some point it starts failing w/ the `Couldn't tcp connect to target` output message. We can end the process here (although normally you would wait until it finishes on its own).

From this output we know *the `STATS` command is not vulnerable*.
### Targeting `TRUN` command
For `TRUN` we'll do the same thing, except change the `s_string()` variable parameter to `"TRUN "`. Let's send it (in the same way):
```bash
generic_send_tcp $t 9999 trun.spk 0 0

```
This time when we run the command, the immunity debugger shows that the vulnserver process pauses and 




> [!Resources]
> -  [Vulnserver](https://thegreycorner.com/vulnserver.html) 
> - [Immunity Debugger](https://www.immunityinc.com/products/debugger/) 