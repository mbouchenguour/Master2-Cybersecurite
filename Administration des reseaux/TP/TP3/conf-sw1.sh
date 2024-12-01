ovs-vsctl set port eth1 tag=10
ovs-vsctl set port eth2 tag=20
ovs-vsctl set port eth3 trunks=10,20
