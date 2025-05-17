---
aliases:
  - linux file descriptors
  - file descriptor
  - file descriptors
---
INIT
# Linux File Descriptors
Check out this cool [stack overflow](https://stackoverflow.com/questions/16995425/how-does-cmd-dev-null-21-work) (explains `/dev/null 2>&1`) 
> Note that Bash processes left to right; thus Bash sees `>/dev/null` first (which is the same as `1>/dev/null`), and sets the file descriptor 1 to point to /dev/null instead of the stdout. Having done this, Bash then moves rightwards and sees `2>&1`. This sets the file descriptor 2 **to point to the same file** as file descriptor 1 (and not to file descriptor 1 itself!!!! (see [this resource on pointers](http://cslibrary.stanford.edu/106/) for more info) . Since file descriptor 1 points to /dev/null, and file descriptor 2 points to the same file as file descriptor 1, file descriptor 2 now also points to /dev/null. Thus both file descriptors point to /dev/null, and this is why no output is rendered.

The author goes on to say...
> From section 3.6.4 [here](https://www.gnu.org/software/bash/manual/html_node/Redirections.html), we see that we can use the operator `&>` to redirect both stdout and stderr. Thus, to redirect both the stderr and stdout output of any command to `\dev\null` (which deletes the output), we simply type `$ command &> /dev/null` or in case of my example:
> `$ (echo "stdout"; echo "stderror" >&2) &>/dev/null`





> [!Resources]
> - [Cool StackOverflow](https://stackoverflow.com/questions/16995425/how-does-cmd-dev-null-21-work)
