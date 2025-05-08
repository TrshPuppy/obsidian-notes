
# Alternatives to Socat for Port Forwarding (Unix)
## `rinetd`
[_rinetd_](https://github.com/samhocevar/rinetd) is a tool which *runs as a daemon*. This makes it ideal for *long term* port forwarding, but also makes it finicky for short term port forwarding.
## `netcat`
We can also use [netcat](../../../cybersecurity/TTPs/exploitation/tools/netcat.md) combined with a [_FIFO_](https://man7.org/linux/man-pages/man7/fifo.7.html) named pipe file. Here is an example [bash script](https://gist.github.com/holly/6d52dd9addd3e58b2fd5):
```bash
#!/usr/bin/env bash

set -e

if [ $# != 3 ]; then

        echo 'Usage: nc-tcp-forward.sh $FRONTPORT $BACKHOST $BACKPORT' >&2
        exit 1
fi

FRONTPORT=$1
BACKHOST=$2
BACKPORT=$3

FIFO=/tmp/backpipe

trap 'echo "trapped."; pkill nc; rm -f $FIFO; exit 1' 1 2 3 15

mkfifo $FIFO
while true; do
        nc -l $FRONTPORT <$FIFO | nc $BACKHOST $BACKPORT >$FIFO
done
rm -f $FIFO
```
## `iptables`
If we *have root privileges* we could use [iptables](../../../CLI-tools/linux/local/iptables.md) to create port forwards. The setup for any given host depends on how the host *is already configured*. Additionally, to port forward on linux, we have to ensure the interface is *enabled for forwarding packets*. An interface can be enabled for forwarding by *writing a `1`* to `/proc/sys/net/ipv4/conf/[interface]/forwarding`.


> [!Resources]
> - [_rinetd_](https://github.com/samhocevar/rinetd)
> - [GitHub Gist (holly): nc-tcp-forward.sh](https://gist.github.com/holly/6d52dd9addd3e58b2fd5)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.