
# `utmpdump` Command
> The `utmpdump` utility does (almost) exactly what its name suggests: it dumps the contents of the `/var/log/utmp` file to your screen. Actually, it dumps _either_ the `utmp` or the `wtmp` file, depending on which you specify. Of course, the file you specify doesn’t have to be located in `/var/log` or even named `utmp` or `wtmp`, and it doesn’t even have to be in the right format. If you feed `utmpdump` a text file, it dumps the contents to your screen (or a file, with the `--output` option) in a format that’s predictable and easy to parse.
> 
> Normally, of course, you would just use `who` or `w` to parse login records, but `utmpdump` is useful in many instances.
> - Files can get corrupted. While `who` and `w` are often able to detect corruption themselves, `utmpdump` is ever more tolerant because it does no parsing on its own. It renders the raw data for you to deal with.
> - Once you’ve repaired a corrupted file, `utmpdump` can patch your changes back in.
> - Sometimes you just want to parse data yourself. Maybe you’re looking for something that `who` and `w` aren’t programmed to look for, or maybe you’re trying to make correlations all your own.
>  
>  Whatever the reason, `utmpdump` is a useful tool to extract raw data from the login records.
>  
>  If you have repaired a corrupted login log, you can use `utmpdump` to write your changes back to the master log:
>  
>  `$ sudo utmpdump -r < wtmp.fix > /var/log/wtmp`

> [!Resources]
> - [RedHat](https://www.redhat.com/sysadmin/monitor-users-linux)
