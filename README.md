# nf_udp_echo
Netfilter UDP echo kernel-module (echoing only configured ports).

The module creates file /proc/nf_udp_echo/ports.
To configure you need to write sequence of comma-separated ports, e.g.:
$ echo 11111,22222 > /proc/nf_udp_echo/ports.

To view configured ports read from /proc/nf_udp_echo/ports:
$ cat /proc/nf_udp_echo/ports.
