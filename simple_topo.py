#!/usr/bin/python

# sudo -E python simple_topo.py

from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def MyTopo():

    net = Mininet()
    c0 = net.addController('c0', controller=RemoteController, port=6633)

    servers = 2
    clients = 2
    spine_switches = 1

    hosts = []
    switches = []

    hosts_cnt = 0

    # Add Hosts
    for h in range(servers):
        hosts.append(net.addHost('h%s' % (h+1), mac="00:00:00:00:00:0%s" % (h+1)))
        hosts_cnt += 1

    for h in range(clients):
        hosts.append(net.addHost('h%s' % (h+1+servers), mac="00:00:00:00:00:0%s" % (h+1+servers)))
        hosts_cnt += 1

    # Add Switches
    # s6 is the load balancer
    for s in range(servers + clients + spine_switches):
        switches.append(net.addSwitch('s%s' % (s+1), cls=OVSKernelSwitch, protocols='OpenFlow13'))

    # Add links
    for x in range(servers + clients):
        net.addLink(hosts[x], switches[x])

    for x in range(servers):
        for y in range (spine_switches):
            net.addLink(switches[servers + clients + y], switches[x])

    for x in range(clients):
        for y in range (spine_switches):
            net.addLink(switches[x + servers], switches[servers + clients + y])

    # Start network
    net.build()

    # Attaching Controllers to Switches
    for s in switches:
        s.start([c0])

    # Setting interface only routes and not default routes
    # h0.cmd("route del -net 0.0.0.0")
    

    # Start command line 
    CLI(net)

    # Stop network
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    MyTopo()