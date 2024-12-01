ip tunnel add tun6R1 mode sit remote any local 10.0.0.1 ttl 64
ip link set tun6R1 up
ip addr add 2002:0A00:0001::1/48 dev tun6R1

ip -6 route add fd00:0:0:02::/64 via ::10.0.0.2 dev tun6R1
ip -6 route add fd00:0:0:03::/64 via ::10.0.2.2 dev tun6R1
