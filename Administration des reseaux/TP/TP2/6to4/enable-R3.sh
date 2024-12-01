ip tunnel add tun6R3 mode sit remote any local 10.0.2.2 ttl 64
ip link set tun6R3 up
ip addr add 2002:0A00:0202::1/48 dev tun6R3
ip -6 route add fd00:0:0:02::/64 via ::10.0.2.1 dev tun6R3
ip -6 route add fd00:0:0:01::/64 via ::10.0.0.1 dev tun6R3
