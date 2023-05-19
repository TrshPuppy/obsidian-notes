
# Linux File System Hierarchy
Everything in Linux is a file.

## `tree`
`tree` is a command which can show you the file hierarchy relative to your current directory:
```bash
trshpuppy@trshpile:/var/log$ tree
.
├── alternatives.log
├── alternatives.log.1
├── alternatives.log.10.gz
├── alternatives.log.2.gz
├── alternatives.log.3.gz
├── alternatives.log.4.gz
├── alternatives.log.5.gz
├── alternatives.log.6.gz
├── alternatives.log.7.gz
├── alternatives.log.8.gz
├── alternatives.log.9.gz
├── apport.log
├── apport.log.1
├── apport.log.2.gz
├── apport.log.3.gz
...
```
Can also use `tree ..` to list the parent directory tree.

## Special Files:
Every file has a file handle which is a number. Every file handle has a number.

### stdin (`fh 0`):
Input from the console/keyboard, or from a redirect to stdin. Can redirect data to `stdin` and have it be processed through a pipe.

### stdout (`fh 1`):
Output to the user.

### stderr (`fh 2`):
Error output to the user.

### *pipe (`|`)* 
```bash
firstcommand | seccondcommand
```
Allows you to "pipe" anything from the `stdout` of the first command to the `stdin` of the second command. The command before the pipe *has to complete* before output can be piped to the second command (which *can* take up a lot of memory).

### Example:
```bash
command > file.txt # > only captures stdout of the command
command &> file.txt # &> captures stdout AND stderr of the command
```

## Parsing Logs:
### `cat`
Means 'concatenate.' Can take 2 files as arguments and concatenate them:
```bash
# Create two random files:
 echo 'file1' > 'file1.txt'
 echo 'file2' > 'file2.txt'
 # concat them
 cat file1
 cat: file1: No such file or directory
 cat file1.txt
 file1
 # Create a string w/ an executable command
 # Need to wrap in double quotes or command inside string will not execute
 # With double quotes: "${thing}" is a variable, "$(thing)" is an executable
 echo "$(uuidgen)" > file1.txt
 echo "$(uuidgen)" > file2.txt
 cat file1.txt file2.txt # concat both files:
 71263548-dd90-b3b3-dklfjkdjl
 78361783-dd89-b4b4-dkfdhdjkh # random/ incorrect uuids 
 # create a 3rd file from the two concatenated files:
 cat file1.txt file2.txt > file3.txt
 cat file3.txt
 71263548-dd90-b3b3-dklfjkdjl
 78361783-dd89-b4b4-dkfdhdjkh 
 ```

### `grep`:
grep can be used to search through logs by having the concatenated log piped to grep and/or passing the filename to grep:
```bash
cat dpkg.log | grep trigproc
2023-04-04 10:28:28 trigproc man-db:amd64 2.10.2-1 <none>
2023-04-04 10:28:28 trigproc libc-bin:amd64 2.35-0ubuntu3.1 <none>
2023-04-04 10:28:31 trigproc mailcap:all 3.70+nmu1ubuntu1 <none>
2023-04-04 10:28:32 trigproc desktop-file-utils:amd64 0.26-1ubuntu3 <none>
...
```
vs:
```bash
grep trigproc dpkg.log
2023-04-04 10:28:28 trigproc man-db:amd64 2.10.2-1 <none>
2023-04-04 10:28:28 trigproc libc-bin:amd64 2.35-0ubuntu3.1 <none>
2023-04-04 10:28:31 trigproc mailcap:all 3.70+nmu1ubuntu1 <none>
2023-04-04 10:28:32 trigproc desktop-file-utils:amd64 0.26-1ubuntu3 <none>
2023-04-04 10:28:32 trigproc hicolor-icon-theme:all 0.17-2 <none>
2023-04-04 10:28:32 trigproc gnome-menus:amd64 3.36.0-1ubuntu3 <none>
...
```

Can also use `grep -e` or `egrep` to pass a regex to grep:
```bash
egrep '[0-9]{4}' dpkg.log
```

### Number of lines/ words:
To see how many lines there are in a file, cat the file and pipe with `wc -l`, (*always includes one extra line in the count*).
- `wc` stands for word count
- `l` stands for lines

`wc -c` will tell you how many characters there are *including new line (\n) characters.*

### `cut`
Piping a log output (concatenated) to cut can help you "cut" the file into pieces based on its parts.

*For example:* If you want to cut a log file based by date, you can cut split each line on whitespace (`" "`) and refer to each piece as field 1, field 2, etc.
```bash
cat dpkg.log | cut -d ' ' -f 1
2023-04-19
2023-04-19
2023-04-19
2023-04-19
2023-04-19
2023-04-19
2023-04-19
...
```

You can also organize by uniqueness using `uniq`(in this example, to see how many unique dates the log contains):
```bash
cat dpkg.log | cut -d ' ' -f 1 | uniq
2023-04-04
2023-04-05
2023-04-07
2023-04-08
2023-04-12
2023-04-13
2023-04-17
2023-04-18
2023-04-19
...
```

You can give `uniq` the `-c` flag to then list the number of items present in the log for each unique date:
```bash
cat dpkg.log | cut -d ' ' -f 1 | uniq -c
    123 2023-04-04
     62 2023-04-05
    238 2023-04-07
     34 2023-04-08
     19 2023-04-12
    174 2023-04-13
    131 2023-04-17
     25 2023-04-18
    254 2023-04-19
...
```

> [!Resources:]
> All of this information is from a video made for me by a knowledgeable friend.

