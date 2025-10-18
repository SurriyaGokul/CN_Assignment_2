from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink

class Topology(Topo):
    def build(self):
        # Adding switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        # Adding hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        dns = self.addHost('dns', ip='10.0.0.5/24')

        # Adding links with bandwidth and delay
        self.addLink(h1, s1, cls=TCLink, bw=100, delay='2ms')
        self.addLink(h2, s2, cls=TCLink, bw=100, delay='2ms')
        self.addLink(h3, s3, cls=TCLink, bw=100, delay='2ms')
        self.addLink(h4, s4, cls=TCLink, bw=100, delay='2ms')
        self.addLink(dns, s2, cls=TCLink, bw=100, delay='1ms')

        # Addig the switch interconnections
        self.addLink(s1, s2, cls=TCLink, bw=100, delay='5ms')
        self.addLink(s2, s3, cls=TCLink, bw=100, delay='8ms')
        self.addLink(s3, s4, cls=TCLink, bw=100, delay='10ms')

if __name__ == '__main__':
    setLogLevel('info')
    topo = Topology()
    net = Mininet(topo=topo, link=TCLink,controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633))
    net.start()

    print("\nTesting connectivity between all hosts:")
    net.pingAll()

    print("\nNetwork is ready. Use CLI for manual testing.")
    CLI(net)

    net.stop()
