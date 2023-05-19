
# Permissions and Privileges in Linux:

## Permissions:
The output of `ls -al` is a list of all the files and directories in the current/ parent directory *with the addition* of some metadata.

The `-l` flag means "long" form, or "list more information about each file/ directory". This includes file type, size, timestamp, permissions, owner, last access date/ time, etc.

The `-a` flag means `all` or list all files/ directories including hidden ones (which have a `.` at the beginning of their name).

The output looks like this:
```bash
trshpuppy@trshheap:~$ ls -al
total 100
drwxr-xr-x 16 trshpuppy trshpuppy 4096 May 17 11:21 .
drwxr-xr-x  3 root      root      4096 Sep 18  2022 ..
-rw-------  1 trshpuppy trshpuppy 2546 May 19 14:32 .bash_history
-rw-r--r--  1 trshpuppy trshpuppy  220 Sep 18  2022 .bash_logout
...
```

Cutting or splitting the output on the `' '` can help distinguish the different parts of the output:
```bash
trshpuppy@trshheap:~$ ls -al | cut -d ' ' -f 1
total
drwxr-xr-x
drwxr-xr-x
-rw-------
-rw-r--r--
...
```
`-d` tells cut to cut on this "delimiter" (`' '` which is the whitespace character). The `-f` flag stands for `field`, so asking cut for `-f 1` means "give me the first field".

We can cut again to breakdown each part of field one:
```bash
trshpuppy@trshheap:~$ ls -al | cut -c 1
t
d
d
-
...
```
We used `-c 1` to tell cut to cut on characters, and to give us only the first character. Ignoring the first `t` (which belongs to `total`) we can see the types of each listed file and directory. 

- `d` denotes a directory
- `-` denotes a *regular* file

The next 9 characters (or bits) are the permissions for each file. Each set of 3 characters is the permissions for the file owner (first set), group members (second set), and others (last set). Each set contains 3 bits, one for read, write, and execute.
```bash
trshpuppy@trshheap:~$ ls -al | cut -c 2-10
otal 100
rwxr-xr-x
rwxr-xr-x
rw-------
rw-r--r--
...
```
Each permission bit w/i a set of bits will either be a letter or a `-`. `r` stands for read and denotes that this user/ group has read permissions. `w` is for write, `x` is for execute, and `-` means that permission is not granted.

So, for the first line:
```
rwxr-xr-x
```
- The owner (`rwx`) has read, write and execution permissions.
- Users in the owner's group (`r-x`) only have read and execute permissions.
- Other users (the last set of `r-x`) also only have read and execute permissions.

### Pentesting:
For pentesting, it's ideal to find files which allow full permissions so you can write and execute to the disk. A good example of a directory that allows full access across all users/groups is the `/tmp` folder:
```bash
trshpuppy@trshheap:~$ ls -al /tmp
total 164
drwxrwxrwt  9 root      root      4096 May 17 09:18 .
# the '.' in the last field denotes the parent/ root folder (/tmp)
```

### Changing Permissions:
If you create a file in Linux it will inherit the permissions associated with your user context. Depending on your shell context, you may create a new file but find you have no permissions to read, write, or execute it.

#### Using `chmod +`
To update the permissions of a file, use the `chmod` command:
```bash
1  trshpuppy@trshheap:~$ echo "hello" > hello.txt
2  trshpuppy@trshheap:~$ cat hello.txt
3  hello
4  trshpuppy@trshheap:~$ ls -al | grep "hello.txt"
5  -rw-r--r--  1 trshpuppy trshpuppy    6 May 19 15:08 hello.txt
6  # I have no execution permission on the file I just made
7  # . 
8  trshpuppy@trshheap:~$ chmod +rwx hello.txt
9  trshpuppy@trshheap:~$ ls -al | grep "hello.txt"
10 -rwxr-xr-x  1 trshpuppy trshpuppy    6 May 19 15:08 hello.txt
```
On line `8` we use `chmod +rwx` to add all three file permissions to our `hello.txt` file.

#### Using `chmod` numbers:
A faster way to update permissions with `chmod` is to use give it numbers as flags. To do this, you just give three numbers, each from 0-7, to `chmod`.

Each combination of permissions results in a number between 0 and 7. For example, the number `0` is `- - -`, or no permissions at all. the number `1` is `- - 1`, or only execution permissions.  The number `2` is `-w-` or only write permissions. And the number `4` is `4 - -` or only read permissions (the numbers represent bits being turned on or off).
| Num | Permissions | Total | Binary |
| :--: | :--------: | :---: | :-:|
| 0 | --- | 0+0+0 | 000 |
| 1 | --x | 0+0+1 | 001 |
| 2 | -w- | 0+2+0 | 010 |
| 3 | -wx | 0+2+1 | 011 |
| 4 | r-- | 4+0+0 | 100 |
| 5 | r-x | 4+0+1 | 101 |
| 6 | rw- | 4+2+0 | 110 |
| 7 | rwx | 4+2+1 | 111 |

So, to give everybody full permissions on a file, the command would be:
```bash
trshpuppy@trshheap:~$ chmod 777 hello.txt
trshpuppy@trshheap:~$ ls -al | grep "hello.txt"
-rwxrwxrwx  1 trshpuppy trshpuppy    6 May 19 15:08 hello.txt
```

> [!Resources:]
> [GNU ls Documentation](https://www.gnu.org/software/coreutils/manual/html_node/What-information-is-listed.html)
> [How to Geek: ls Command](https://www.howtogeek.com/448446/how-to-use-the-ls-command-on-linux/)
> 
> 