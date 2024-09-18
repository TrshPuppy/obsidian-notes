
# `ip` Command:
This linux networking command can be used to show and manipulate network devices and settings.
```
ip [OPTIONS] OBJECT {COMMAND | help}
```
## Useful options:
```bash
SYNOPSIS
       ip [ OPTIONS ] OBJECT { COMMAND | help }
       ip [ -force ] -batch filename
       OBJECT := { link | address | addrlabel | route | rule | neigh | ntable | 
	       tunnel | tuntap | maddress | mroute | mrule | monitor | xfrm | netns 
	       | l2tp | tcp_metrics | token | macsec }

       OPTIONS := { -V[ersion] | -h[uman-readable] | -s[tatistics] | -d[etails] 
	       | -r[esolve] | -iec | -f[amily] {inet | inet6 | link } | -4 | -6 | -I 
	       | -D | -B | -0 | -l[oops] { maximum-addr-flush-attempts } |
	       -o[neline] | -rc[vbuf] [size] | -t[imestamp] | -ts[hort] | -n[etns] 
	       name | -N[umeric] | -a[ll] | -c[olor] | -br[ief] | -j[son] | 
	       -p[retty] }
```
### ``ip link list``:
Shows all the available network interfaces (``link`` = network device, ``list`` = show all objects / devices)
### `ip maddress`:
Show [MAC Addresses](/networking/OSI/MAC-addresses.md) of network devices.
### `ip link set x <up/down>`:
Bring a network interface up or down.
### ``ip address show``:
Shows the `address` (IPv4 or IPv6) of a given device.

> [!Resources]
> `man ip`
> [How To Geek: ip Command](https://www.howtogeek.com/657911/how-to-use-the-ip-command-on-linux/#using-ip-with-network-interfaces)

