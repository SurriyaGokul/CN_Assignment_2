#!/usr/bin/env python3
"""
Configure Mininet Hosts to Use Custom DNS Resolver
Sets up /etc/resolv.conf on all hosts to point to 10.0.0.5

This script:
1. Starts the Mininet topology
2. Configures DNS host (10.0.0.5) and starts DNS server
3. Configures all other hosts to use 10.0.0.5 as DNS server
4. Tests connectivity
5. Opens CLI for manual testing

Usage:
    sudo python3 setup_custom_dns.py
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import os


class DNSTopology(Topo):
    """Network topology with DNS server"""
    
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

        # Adding switch interconnections
        self.addLink(s1, s2, cls=TCLink, bw=100, delay='5ms')
        self.addLink(s2, s3, cls=TCLink, bw=100, delay='8ms')
        self.addLink(s3, s4, cls=TCLink, bw=100, delay='10ms')


def configure_dns_server(net):
    """Configure and start custom DNS server on dns host"""
    info('\n*** Configuring DNS Server (10.0.0.5)\n')
    
    dns = net.get('dns')
    
    # Configure DNS host networking
    dns.cmd('echo "nameserver 8.8.8.8" > /etc/resolv.conf')
    
    # Copy DNS server script to /tmp
    dns.cmd('cp custom_dns_server.py /tmp/')
    
    # Start DNS server in background
    info('*** Starting Custom DNS Server on port 53...\n')
    dns.cmd('python3 /tmp/custom_dns_server.py > /tmp/dns_server_output.log 2>&1 &')
    
    # Wait for server to start
    time.sleep(2)
    
    # Check if server is running
    result = dns.cmd('netstat -ulnp | grep :53')
    if '53' in result:
        info('✓ DNS Server is running on port 53\n')
        return True
    else:
        info('✗ DNS Server failed to start\n')
        info(f'Output: {result}\n')
        return False


def configure_hosts_to_use_custom_dns(net):
    """Configure all hosts to use custom DNS resolver at 10.0.0.5"""
    info('\n*** Configuring Hosts to Use Custom DNS Server (10.0.0.5)\n')
    
    hosts = ['h1', 'h2', 'h3', 'h4']
    
    for host_name in hosts:
        host = net.get(host_name)
        
        # Set DNS server in resolv.conf
        host.cmd('echo "nameserver 10.0.0.5" > /etc/resolv.conf')
        
        # Verify configuration
        result = host.cmd('cat /etc/resolv.conf')
        info(f'{host_name}: {result}')
        
        if '10.0.0.5' in result:
            info(f'✓ {host_name} configured to use DNS server at 10.0.0.5\n')
        else:
            info(f'✗ {host_name} DNS configuration failed\n')


def test_dns_resolution(net):
    """Test DNS resolution from hosts"""
    info('\n*** Testing DNS Resolution\n')
    
    hosts = ['h1', 'h2', 'h3', 'h4']
    test_domain = 'google.com'
    
    for host_name in hosts:
        host = net.get(host_name)
        info(f'\nTesting DNS resolution on {host_name} for {test_domain}:\n')
        
        # Test with dig
        result = host.cmd(f'dig +short @10.0.0.5 {test_domain} A')
        info(f'{host_name} dig result: {result}')
        
        # Test with host command
        result2 = host.cmd(f'host {test_domain}')
        info(f'{host_name} host result: {result2}')


def show_status(net):
    """Show current status and instructions"""
    info('\n' + '='*80 + '\n')
    info('CUSTOM DNS RESOLVER CONFIGURATION COMPLETE\n')
    info('='*80 + '\n')
    info('\nNetwork Setup:\n')
    info('  - DNS Server running at: 10.0.0.5:53\n')
    info('  - Hosts configured: h1, h2, h3, h4\n')
    info('  - All hosts use 10.0.0.5 as DNS server\n')
    info('\nLog Files:\n')
    info('  - DNS Server output: /tmp/dns_server_output.log\n')
    info('  - DNS Query logs: /tmp/dns_resolver.log\n')
    info('  - JSON logs: /tmp/dns_queries.json\n')
    info('\nUseful Commands in CLI:\n')
    info('  h1 dig google.com              # Test DNS from h1\n')
    info('  h1 host example.com            # Test DNS from h1\n')
    info('  dns cat /tmp/dns_resolver.log  # View DNS logs\n')
    info('  dns cat /tmp/dns_queries.json  # View query logs\n')
    info('  h1 cat /etc/resolv.conf        # Check DNS config\n')
    info('\nTo test with PCAP domains:\n')
    info('  Use the test_dns_from_pcap.py script\n')
    info('='*80 + '\n')


def main():
    """Main function"""
    setLogLevel('info')
    
    info('\n*** Creating Network Topology\n')
    topo = DNSTopology()
    net = Mininet(topo=topo, link=TCLink, 
                  controller=lambda name: OVSController(name, ip='127.0.0.1', port=6633))
    
    info('\n*** Starting Network\n')
    net.start()
    
    info('\n*** Testing Base Connectivity\n')
    net.pingAll()
    
    # Configure DNS server
    dns_started = configure_dns_server(net)
    
    if not dns_started:
        info('\n✗ Failed to start DNS server. Check logs.\n')
        net.stop()
        return
    
    # Configure hosts to use custom DNS
    configure_hosts_to_use_custom_dns(net)
    
    # Test DNS resolution
    test_dns_resolution(net)
    
    # Show status
    show_status(net)
    
    info('\n*** Entering CLI (type "exit" to quit)\n')
    CLI(net)
    
    info('\n*** Stopping Network\n')
    
    # Kill DNS server
    dns = net.get('dns')
    dns.cmd('pkill -f custom_dns_server.py')
    
    net.stop()


if __name__ == '__main__':
    # Check if running as root
    if os.geteuid() != 0:
        print("Error: This script must be run as root (use sudo)")
        exit(1)
    
    main()
