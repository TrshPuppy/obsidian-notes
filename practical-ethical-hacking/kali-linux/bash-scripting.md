
# Bash Scripting
Bash (Bourne Again Shell) is a Linux shell and command/ coding language. It's the default shell for most Linux distros. Others include Z shell (zsh), Bourne Shell (sh), C Shell (csh), etc..

## Linux Shells:
A shell is an interpreter program in the command line which can be used to send commands to the operating system. It can be considered the OS's interactive interface, and the outer-most layer of the kernel. 

It allows users and/ or programs to send messages and signals to the operating system and its low-level utilities.
![](/nested-repos/PNPT-study-guide/PNPT-pics/bash-scripting-1.png)
![](/PNPT-pics/bash-scripting-1.png)<br>
-[Phoenix Nap: 8 Types of Linux Shells](https://phoenixnap.com/kb/linux-shells)

## Ping Sweeping:
A "ping sweeper" is a script that will [ping](/CLI-tools/ping.md) a device to see if it's connected/ alive and return the results.

Because `ping` (on Linux) will ping continuously, you can use `-c <number>` to tell it to ping only `<number>` amount of times (`-c` stands for `count`). The response from `ping` can be appended to a file using `>` or `>>`.

### Using [grep](/computers/linux/filesystem-hierarcy.md):
[`grep`](/computers/linux/filesystem-hierarcy.md) is a Linux CLI tool that allows you to search the output of a file or program (everything in Linux is a file) for a specific/ unique string. In the ping sweeper, we can use `grep` to filter responses from multiple pings to only include pings which were successful.

Because successful pings will output a string which includes the amount of bytes in the ping response, we can pipe (`|`) the output of `ping` to `grep` and ask `grep` to filter out all responses which include the substring "`64 bytes`".
```bash
ping 69.69.69.69 -c 1 > response.txt
cat response.txt | grep "64 bytes from"
64 bytes from 69.69.69.69: icmp_seq=1 ttl=56 time=24.2 ms
```

### Using [cut](/computers/linux/filesystem-hierarchy.md):
You can then pipe to `cut -d " " -f 4` ( [cut](/computers/linux/filesystem-hierarchy.md) on spaces, get field 3) to get the IP address which responded to the ping.
```bash
ping 69.69.69.69 -c 1| grep "64 bytes from" | cut -d " " -f 4
69.69.69.69:
```

### Using tr (translate):
Since the output still has a colon left on it, we can pretty it up even more with the `tr` (`translate`) command to get rid of the `:`.
```bash
ping 69.69.69.69 -c 1| grep "64 bytes from" | cut -d " " -f 4 | tr -d ":"
69.69.69.69
```

## Building a Ping Sweeper:
The commands we just used can be automated by extracting them into a bash script:

### 1. Text Editor
Open nano and put the following line at the top:
```bash
#!/bin/bash
```
This is called a "shebang" and it tells the compiler/ machine that the following script is in bash and this is where bash is located in the filesystem.

### 2. Paste your code from the command line
```bash
ping 69.69.69.69 -c 1| grep "64 bytes from" | cut -d " " -f 4 | tr -d ":"
```
Pasting your code like this into the bash script is fine, and calling the script will run the commands just like running them in the terminal. However, you want to check multiple IP Addresses within a [subnet](/nested-repos/PNPT-study-guide/practical-ethical-hacking/networking/subnetting.md). To run this command enough times, you need to make a for loop.

### 3. Bash for-loop
A for-loop in coding allows for an expression to run multiple times until specific conditions are met. For the ping sweeper, we're assuming we're pinging IP Addresses w/i a `/24` subnet, meaning there are 256 total addresses.

So the for-loop needs to run 254 times (-2 for the network and broadcast addresses) to cover the entire subnet. Most for-loops are written with a boolean condition which decides when the loop will stop executing the code inside it. For this for-loop our condition is basically "for each number that is *true* (exists) from 1 to 254, execute this code."
```bash
#!/bin/bash

for ip in `seq 1 254`; do
	ping 69.69.69.$ip -c 1| grep "64 bytes from" | cut -d " " -f 4 | tr -d ":" &
done
```
Treat `ip` and `$ip` as placeholder variables which during each cycle of the for loop will contain current number between 1 and 254. `seq 1 254` is "the sequence between the starting number `1` and the ending number `254`" with both numbers being inclusive.

The `&` (ampersand) will allow each cycle of the for loop to run concurrently *as separate processes*, which will make this run much faster (but also require more resources/ memory).

### 4. Providing/ handling arguments
In Bash (and other coding languages/ scripts, etc.) the first argument given to the script is always itself. The subsequent arguments are what was given to the script in the command line when it was called.
```bash
./ping_sweep.sh 69.69.69.69
# ./ping_sweep.sh is arg 1 ($0)
# 69.69.69.69 is arg 2 ($1)
```

To refer to arguments in a script with bash, you use `$` w/ the argument's number. So the first argument (the script itself) is `$0`, the second is `$1`. We can make use of arguments in our script so we can give our program a starting IP Address:
```bash
#!/bin/bash

for ip in `seq 1 254`; do
	ping -c 1 $1.$ip | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
done
```
So now we can scan a specific address space like `69.69.69` by calling our script from the command line like this:
```bash
./ping_sweep.sh 69.69.69
```

### 5. If statements
Running this code as is can be buggy, especially if we run it *without giving it any arguments.* Adding and if statement can easily fix this:
```bash
#!/bin/bash

if [ "$1" == "" ]
then
    echo "Please specifiy an IP Address."
    echo "Syntax: ./ping_sweep.sh xxx.xxx.xxx"
else
    for ip in `seq 1 254`; do
        ping -c 1 $1.$ip | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
    done
fi
```

### 6. Creating a file
Right now, the script is outputting to the command line, but the information is not saved beyond that. We should add to our script so that it creates a list of IP Addresses, then we can use that list for other scans like [`nmap`](/CLI-tools/nmap.md):
```bash
#!/bin/bash

if [ "$1" == "" ]
then
    echo "Please specifiy an IP Address."
    echo "Syntax: ./ping_sweep.sh xxx.xxx.xxx"
else
    for ip in `seq 1 254`; do
        ping -c 1 $1.$ip | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" >> ip_list.txt &
    done
fi
```

Now we can run nmap on our list in a command like this in the CLI:
```bash
for ip in $(cat ip_list.txt); do nmap $ip; done
```

## Pretty up the Ping Sweeper:
```bash
#!/bin/bash

if [ "$1" == "" ]
then
    echo "Please specifiy an IP Address."
    echo "Syntax: ./ping_sweep.sh xxx.xxx.xxx"
else
    for ip in `seq 1 254`; do
        ping -c 1 $1.$ip | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" >> ip_list.txt &
    done
fi

for ping in $(cat ip_list.txt); do
        nmap $ping
done
```

> [!Resources]
> - [Phoenix Nap: 8 Types of Linux Shells](https://phoenixnap.com/kb/linux-shells)
> - [Wikipedia: Bash](https://en.wikipedia.org/wiki/Bash_(Unix_shell))
> - [Linux Handbook: Bash Beginner Series](https://linuxhandbook.com/if-else-bash/)

> [!My previous notes (linked in text)]
> - [ping](https://github.com/TrshPuppy/obsidian-notes/blob/main/CLI-tools/ping.md)
> - [grep and cut](https://github.com/TrshPuppy/obsidian-notes/blob/main/computers/linux/filesystem-hierarchy.md)
> - [Subnetting](https://github.com/TrshPuppy/PNPT-study-guide/blob/main/practical-ethical-hacking/networking/subnetting.md)
> - [nmap](https://github.com/TrshPuppy/obsidian-notes/blob/main/CLI-tools/nmap.md)


