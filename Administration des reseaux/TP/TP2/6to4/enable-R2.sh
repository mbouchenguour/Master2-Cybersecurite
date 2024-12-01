ip tunnel del tun61R2 2>/dev/null || true
ip tunnel del tun63R2 2>/dev/null || true

ip tunnel add tun61R2 mode sit remote any local 10.0.0.2 ttl 64
ip link set dev tun61R2 up
ip -6 addr add 2002:0a00:0002::1/48 dev tun61R2


ip tunnel add tun63R2 mode sit remote any local 10.0.2.1 ttl 64
ip link set dev tun63R2 up
ip -6 addr add 2002:0a00:0201::1/48 dev tun63R2


ip -6 route add fd00:0:0:01::/64 via ::10.0.0.1 dev tun61R2
ip -6 route add fd00:0:0:03::/64 via ::10.0.2.2 dev tun63R2
