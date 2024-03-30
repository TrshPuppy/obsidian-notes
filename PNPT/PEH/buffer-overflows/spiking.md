
# Spiking w/ Vulnserver
The following notes were created while using [Vulnserver](https://thegreycorner.com/vulnserver.html) and [Immunity Debugger](https://www.immunityinc.com/products/debugger/) on a Windows 10 VM.
## Setup
Once Vulnserver and Immunity Debugger are installed on the vulnerable Windows VM, use `ipconfig` to find the VM's IP address. Verify your attack box and the vulnerable box can talk to each other (using [ping](/CLI-tools/ping.md)).

Then you can connect to Vulnserver from your attack box using [netcat](/cybersecurity/tools/exploitation/netcat.md):
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
Each of the listed commands can be *spiked* to find out whether they are vulnerable to a [buffer-overflow](/cybersecurity/TTPs/exploitation/binary-exploitation/buffer-overflow.md) or not. The point of buffer overflow is to *overwrite the saved `RIP`/ `EIP` frame on the stack* so we can hijack execution flow.

The saved `EIP` is a frame pushed onto the stack before a function in the code is called (and its own frame is pushed onto the stack). The job of the saved `EIP` is to tell the CPU where to resume executing after the function being called has finished executing. If we can overflow the saved `EIP`, then we can replace the value it holds *with the address on the stack* which we know *holds our own malicious code*. That way, when the CPU reads the value in saved `EIP` it will go to the address we've placed there which takes it to our malicious code (and it will begin executing it).

Spiking will tell us which commands are vulnerable because *if we're able to overwrite the saved `RIP` with junk data the program will crash*. So, we're looking for which command will cause the vulnerable program to crash if we overwrite it. 

To test each command, we can use `generic_send_tcp`, a command/ program on Kali:
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
`generic_send_tcp` will take our script and use it to send strings of various lengths, all filled with "0", to the `STATS` command *until the program breaks*.
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

From this output we know *the `STATS` command is not vulnerable*. We can also look at Immunity Debugger. If the program had crashed, we'd be able to see that in the debugger. 
### Targeting `TRUN` command
For `TRUN` we'll do the same thing, except change the `s_string()` variable parameter to `"TRUN "`. Let's send it (in the same way):
```bash
generic_send_tcp $t 9999 trun.spk 0 0
```
This time when we run the command, the immunity debugger shows that the vulnserver process pauses and shows an access violation. This means we were able to *crash vulnserver*. This tells us that the `TRUN` command is vulnerable.
![](PNPT/PNPT-pics/spiking-1.png)
In Immunity Debugger, if we look at the registers, we can see that the buffer allocated for the `TRUN` command *has been overflowed with out `A` characters.* The stack (`ESP`) and base (`EBP`) pointers have also been overflowed on the stack.

And if we look at the value currently held in the `EIP` register, we see `41414141`. '41' is the char code for `A`, which means we've also managed to overflow the instruction pointer, which is our ultimate target.

Based on the [anatomy of the stack](https://trshpuppy.github.io/portfolio/writeups/binary-exploitation) there are frames on the stack which around where the `TRUN` buffer is saved (in its own adjacent frame) which hold the values these registers are *meant to be set to*. The purpose of saving the values for these registers on the stack is to *tell the CPU where to continue executing* after the current *activation frame* has finished executing and has been popped off the stack.

By overflowing the allotted buffer space for `TRUN` we've written data onto the stack *in the direction of those register frames*, and that's why they've been overwritten with our buffer characters.

Now that we've found a vulnerable command, we can move on to [fuzzing](/PNPT/PEH/buffer-overflows/fuzzing.md).

> [!Resources]
> -  [Vulnserver](https://thegreycorner.com/vulnserver.html) 
> - [Immunity Debugger](https://www.immunityinc.com/products/debugger/) 
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.
> - My [writeup on buffer overflows and stack manipulation](https://trshpuppy.github.io/portfolio/writeups/binary-exploitation)