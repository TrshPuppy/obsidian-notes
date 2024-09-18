# Console vs. Terminal vs. Shell vs. TTY
These terms are all closely related & are often used interchangeably, but are technically different. Console, terminal, and shell all originally referred to a *piece of equipment which you could use to interact with a machine*.

These pieces of equipment used to look a lot like typewriters, hence the term 'teletypewriter' or 'tty'.
![](computers/computers-pics/ASR-33_Teletype_terminal_IMG_1658.jpg)
> From [Wikipedia](https://en.wikipedia.org/wiki/Teleprinter#/media/File:ASR-33_Teletype_terminal_IMG_1658.jpg), a Model 33 ASR Teletype used for 'modem-based computing.'

## TTY
In Unix a tty is a [device file](/computers/linux/device-file.md). Besides reading and writing, it also implements additional commands called *'ioctls'*
### Termios
Termios is a function/ interface which represents a terminal interface in Linux. Attached to the termios interface are flags which can be set to different values which then effect the properties and function of the terminal interface.
#### Structure
```bash
		   tcflag_t c_iflag;      /* input modes */
           tcflag_t c_oflag;      /* output modes */
           tcflag_t c_cflag;      /* control modes */
           tcflag_t c_lflag;      /* local modes */
           cc_t     c_cc[NCCS];   /* special characters */
```
#### Raw Mode
You can use the termios structure to put the terminal into raw mode (vs. cooked mode). In raw mode, stdin is available *character by character* instead of line by line, like in cooked mode. Additionally, echo is disabled as well as special processing of input and output. 

Setting the terminal to raw mode usually involves changing the following termios flags:
- `termios_p->c_oflag &= ~OPOST;` : bitwise and w/ the complement of `OPOST` = disabling output processing
- `termios_p->c_iflag &= ~IXON | ICRNL`" bitwise and w/ complement of `IXON` and `ICRNL` = disable input processing (flow control and carriage return )
## Console


> [!Resources]
> - [Wikipedia: Teleprinter](https://en.wikipedia.org/wiki/Teleprinter)
> - [This Question](https://unix.stackexchange.com/questions/4126/what-is-the-exact-difference-between-a-terminal-a-shell-a-tty-and-a-con) from StackExchange