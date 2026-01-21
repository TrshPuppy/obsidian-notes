
# crontab
Linux command for interacting w/ [cron](computers/linux/linux-processes.md) to setup scheduled and automated processes.
## Syntax
```bash
crontab [options]

* * * * *  <command> 
OR 
* * * * * <path/to/script>
```
![](/CLI-tools/CLI-tools-pics/crontab-1.png)
### Setup Crontab for a user:
Crontab is *user specific*. You can check if a user already has a crontab by using the `-l` switch. To create a crontab for a user, use `crontab -e`. This will open a text editor of your choice.

In the text editor, paste a cron job. Now this cron job will run for the user.

> [!Resources]
> - [Linux Handbook](https://linuxhandbook.com/crontab/)

