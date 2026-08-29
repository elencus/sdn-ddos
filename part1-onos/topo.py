#!/usr/bin/env python3

# h1,h2 = hosts
# a1,a2 = attackers
# srv = server (victim)

from mininet.topo import Topo

class DDosTopo(Topo):
    def build(self):
        # switches
        s1 = self.addSwitch('s1') # switch
        s2 = self.addSwitch('s2') # switch near server

        # hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')

        # attackers
        a1 = self.addHost('a1', ip='10.0.0.101/24', mac='00:00:00:00:00:65')
        a2 = self.addHost('a2', ip='10.0.0.102/24', mac='00:00:00:00:00:66')

        # server
        srv = self.addHost('srv', ip='10.0.0.10/24', mac='00:00:00:00:00:0a')


        # links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(a1, s1)
        self.addLink(a2, s1)

        # bottleneck between s1 and s2
        self.addLink(s1, s2, bw=10) # 10 Mbps link

        # server behind s2
        self.addLink(srv, s2)

topos = {'ddos': (lambda: DDosTopo())}
