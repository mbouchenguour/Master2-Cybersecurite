ip tunnel add tun1 mode sit remote 10.0.0.1 local 10.0.0.2 ttl 255
ip link set tun1 up
ip tunnel add tun3 mode sit remote 10.0.2.2 local 10.0.2.1 ttl 255
ip link set tun3 up
ip -6 route add fd00:0000:0000:01::/64 dev tun1
ip -6 route add fd00:0000:0000:03::/64 dev tun3
