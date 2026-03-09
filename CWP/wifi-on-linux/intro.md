# Basic WiFi on Linux
## Interface Information
There are two basic [linux](../../cybersecurity/wordlists/linux.md) commands you can use to get information about your [WiFi](../../networking/wifi/802.11.md) interfaces, `ip` and `iwconfig`. `iw` is the *modern replacement* for `iwconfig` and can give you more detailed info.
### `iw` Basic Commands
- `iw dev`: lists all wireless interfaces
- `iw dev wlan0`: provides detailed info about a specific interface
### `ip` Basic Commands
- `ip link show`: displays all network interfaces including wireless ones
### Naming Schemes
In linux there is the *modern* and the *classic* schemes for naming network interfaces. In the classic scheme, wireless interfaces are named *sequentially* (i.e. `wlan0`, `wlan1`, ...). 

The modern scheme, also called "Predictable Network Interface Names," interfaces are named with more description w/ the name indicating the *physical location* of the interface on the system. For example, in the modern name `wlp2s0`:
- `w`: indicates wireless
- `lp2`: indicates a PCI bus on slot 2
- `s0`: indicates the first device in the slot

In Linux, you can change the interface naming mode by enabling or disabling the modern scheme. However, in wifi hacking, best practice is to *use the classic scheme* because some tools will encounter issues with the modern scheme.

You can change an interfaces name with the `ip link` subcommand:
```bash
ip link set wlx00c0ca9208dc down && ip link set wlx00c0ca9208dc name wlan0 && ip link set wlan0 up
```
**NOTE** that with this command the name will *reset upon reboot* (not permanent).
#### Permanently Changing the Name
To make the name change permanent, you have to add a parmeter to the [kernel](../../computers/concepts/kernel.md) boot configuration. For example, edit the bootloader config file (GRUB) and add `net.ifnames=0 biosdevname=0` to the kernel command line. 

On GRUB-based systems, you can edit the `/etc/default/grub` file and add these parameters:
```bash
GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"
```
Then, update the GRUB config by running `sudo update-grub` and reboot the system. Once rebooted, network interfaces should default to using classic names.


> [!Resources]
> - [Wifi Challenge Academy](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442980-introduction)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.