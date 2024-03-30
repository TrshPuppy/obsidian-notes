
# Linux `sudo` command
`sudo` stands for "super user do" and allows you to run a command as the *root user.* The privilege elevation only exists while running the command. Some distros like Ubuntu will persist the super-user permission for 15 minutes.

Users which are in the "sudoers" group have super-user privileges.

## Root user:
An example of a default user in Linux distros which is in the "sudoers" group is the root user. To login as the root user use `sudo su -` and the context of your shell will change to you being the root user. Exiting or killing the current shell will end the root user privileges for that shell.