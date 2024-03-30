
# Starting & Stopping Linux Services
[Linux Processes](/computers/linux/linux-processes.md) each have a process ID given to them by the kernel based on the order they were started after boot.
## systemctl:
`systemctl` is a command in Linux which allows you to interact with `systemd` which is (usually) PID 1 when a Linux machine boots. `systemd` is the service manager for Linux, and since it is PID 1, *most* processes running on the computer after boot are **child processes of `systemd`**.

Because most processes we want to interact with or use on Linux are a child process of `systemd` we can use `systemd` to control them. This is because they share the same *namespace*.

To interact with `systemd` we have to use the `systemctl` command. There are four options you can give to `systemctl` to manage processes:
1. `start`: starts one or more *units* which are already loaded into memory (units are encapsulations of objects needed for system boot and maintenance)
2. `stop`: deactivate one or more units
3. `enable`: enable one or more unit instances
4. `disable`: disable one or more unit instances.
### Starting a process on boot:
To start a specific process on boot with `systemctl` use: 
```bash
systemctl enable <target process>
# Example:
sudo systemctl enable ssh
# The SSH service will now start up on boot
```

> [!My previous notes (linked in text)]
> - [Linux Processes](https://github.com/TrshPuppy/obsidian-notes/blob/main/computers/linux/linux-processes.md)






