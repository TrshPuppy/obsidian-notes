
# `ip` Command
This linux networking command can be used to show and manipulate network devices and settings.
```
ip [OPTIONS] OBJECT {COMMAND | help}
```
## Useful options
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
### `ip a/address show`
Show all of your network interface cards which have a current [IP address](../../../networking/OSI/3-network/IP-addresses.md) assigned to them.
```bash
┌──(trshpuppy㉿kali)-[~]
└─$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:74:7e:ed brd ff:ff:ff:ff:ff:ff
    inet 192.168.144.131/24 brd 192.168.144.255 scope global dynamic noprefixroute eth0
       valid_lft 1027sec preferred_lft 1027sec
    inet6 fe80::20c:29ff:fe74:7eed/64 scope link noprefixroute
       valid_lft forever preferred_lft forever
10: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none
    inet 192.168.45.190/24 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::70c1:b902:4d33:d5d7/64 scope link stable-privacy proto kernel_ll
       valid_lft forever preferred_lft forever
```
#### `ip r/route`
Show routing table entries.
```bash
┌──(trshpuppy㉿kali)-[~]
└─$ ip r
default via 192.168.144.2 dev eth0 proto dhcp src 192.168.144.131 metric 100
192.168.45.0/24 dev tun0 proto kernel scope link src 192.168.45.190
192.168.144.0/24 dev eth0 proto kernel scope link src 192.168.144.131 metric 100
192.168.157.0/24 via 192.168.45.254 dev tun0
```
### ``ip link list``
Shows all the available network interfaces (``link`` = network device, ``list`` = show all objects / devices).
```bash
┌──(trshpuppy㉿kali)-[~]
└─$ ip link list
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether 00:0c:29:74:7e:ed brd ff:ff:ff:ff:ff:ff
10: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN mode DEFAULT group default qlen 500
    link/none
```
### `ip maddress`
Show [MAC Addresses](/networking/OSI/MAC-addresses.md) of network devices.
```bash
┌──(trshpuppy㉿kali)-[~]
└─$ ip maddress
1:      lo
        inet  224.0.0.1
        inet6 ff02::1
        inet6 ff01::1
2:      eth0
        link  01:00:5e:00:00:01
        link  33:33:00:00:00:01
        link  33:33:ff:74:7e:ed
        inet  224.0.0.1
        inet6 ff02::1:ff74:7eed
        inet6 ff02::1
        inet6 ff01::1
10:     tun0
        inet  224.0.0.1
        inet6 ff02::1
        inet6 ff01::1
```
### `ip link set x <up/down>`
Bring a network interface up or down.

> [!Resources]
> `man ip`
> [How To Geek: ip Command](https://www.howtogeek.com/657911/how-to-use-the-ip-command-on-linux/#using-ip-with-network-interfaces)

