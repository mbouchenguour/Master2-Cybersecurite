ip tunnel add tun2 mode sit remote 10.0.0.2 local 10.0.0.1 ttl 255
ip link set tun2 up
ip tunnel add tun3 mode sit remote 10.0.1.2 local 10.0.1.1 ttl 255
ip link set tun3 up
ip -6 route add fd00:0000:0000:02::/64 dev tun2
ip -6 route add fd00:0000:0000:03::/64 dev tun3
