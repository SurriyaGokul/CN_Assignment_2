#!/usr/bin/env python3
"""
Part C: DNS Configuration with Custom Resolver
Sets up topology and starts custom iterative DNS resolver
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSController
from mininet.nodelib import NAT
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import sys
import os
import time


class TopologyWithNAT(Topo):
    """Network topology with 4 hosts, DNS server, and NAT"""
    def build(self):
        # Adding switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        # Adding hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24', defaultRoute='via 10.0.0.254', inNamespace=True)
        h2 = self.addHost('h2', ip='10.0.0.2/24', defaultRoute='via 10.0.0.254', inNamespace=True)
        h3 = self.addHost('h3', ip='10.0.0.3/24', defaultRoute='via 10.0.0.254', inNamespace=True)
        h4 = self.addHost('h4', ip='10.0.0.4/24', defaultRoute='via 10.0.0.254', inNamespace=True)
        dns = self.addHost('dns', ip='10.0.0.5/24', defaultRoute='via 10.0.0.254', inNamespace=True)

        # NAT node
        nat = self.addNode('nat0', cls=NAT, ip='10.0.0.254/24', 
                          subnet='10.0.0.0/24', inNamespace=False)

        # Links
        self.addLink(h1, s1, cls=TCLink, bw=100, delay='2ms')
        self.addLink(h2, s2, cls=TCLink, bw=100, delay='2ms')
        self.addLink(h3, s3, cls=TCLink, bw=100, delay='2ms')
        self.addLink(h4, s4, cls=TCLink, bw=100, delay='2ms')
        self.addLink(dns, s2, cls=TCLink, bw=100, delay='1ms')
        self.addLink(nat, s2)
        self.addLink(s1, s2, cls=TCLink, bw=100, delay='5ms')
        self.addLink(s2, s3, cls=TCLink, bw=100, delay='8ms')
        self.addLink(s3, s4, cls=TCLink, bw=100, delay='10ms')


def setup_private_resolv_conf(net):
    
    for host_name in ['h1', 'h2', 'h3', 'h4', 'dns']:
        host = net.get(host_name)
        
        # Create private directory for this host
        private_dir = f'/tmp/mininet_{host_name}_etc'
        host.cmd(f'mkdir -p {private_dir}')
        
        # Create a private resolv.conf
        host.cmd(f'echo "# Mininet host {host_name}" > {private_dir}/resolv.conf')
        host.cmd(f'echo "nameserver 8.8.8.8" >> {private_dir}/resolv.conf')
        
        # Mount it over /etc/resolv.conf
        host.cmd(f'mount --bind {private_dir}/resolv.conf /etc/resolv.conf 2>/dev/null || true')
        
    



def start_custom_dns_server(dns_host):
    """Start the custom iterative DNS resolver"""
    
    print("\n" + "="*70)
    print("Starting Custom DNS Server")
    print("="*70)
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dns_script = os.path.join(script_dir, 'custom_dns_server.py')
    
    if not os.path.exists(dns_script):
        print(f"  [ERROR] custom_dns_server.py not found at {dns_script}")
        return False
    
    print(f"  Using: Custom Iterative Resolver")
    print(f"  Script: {dns_script}")
    
    # Install dependencies
    print("  Installing dependencies (dnspython)...")
    dns_host.cmd('pip3 install -q dnspython 2>&1 | grep -v "already satisfied" || true')
    time.sleep(2)
    
    # Start the DNS server
    print("  Starting DNS server on 10.0.0.5:53...")
    dns_host.cmd(f'python3 {dns_script} > /tmp/dns_server.log 2>&1 &')
    time.sleep(3)
    
    # Verify it started
    result = dns_host.cmd('netstat -uln 2>/dev/null | grep :53 || ss -uln 2>/dev/null | grep :53')
    
    if ':53' in result:
        print("  [OK] DNS server is RUNNING on port 53")
        print("  Server log: /tmp/dns_server.log")
        print("  Query log: /tmp/dns_queries.json")
        print("  Resolver log: /tmp/dns_resolver.log")
        
        # Show initial server output
        print("\n  Initial server output:")
        log_output = dns_host.cmd('head -10 /tmp/dns_server.log')
        for line in log_output.split('\n')[:5]:
            if line.strip():
                print(f"     {line}")
        
        return True
    else:
        print("  [ERROR] DNS server failed to start")
        print("\n  Error log:")
        error_log = dns_host.cmd('cat /tmp/dns_server.log')
        for line in error_log.split('\n')[:10]:
            if line.strip():
                print(f"     {line}")
        return False


def configure_hosts(net):
    """Configure all hosts to use custom DNS server"""
    
    print("\n" + "="*70)
    print("Configuring Hosts to Use Custom DNS (10.0.0.5)")
    print("="*70)
    
    for host_name in ['h1', 'h2', 'h3', 'h4']:
        host = net.get(host_name)
        
        # Write to the private mount point
        private_dir = f'/tmp/mininet_{host_name}_etc'
        host.cmd(f'echo "nameserver 10.0.0.5" > {private_dir}/resolv.conf')
        
        # Verify
        result = host.cmd('cat /etc/resolv.conf').strip()
        if '10.0.0.5' in result:
            print(f"  [OK] {host_name}: DNS = 10.0.0.5")
        else:
            print(f"  [WARNING] {host_name}: DNS change may have failed")
    
    print("="*70)


def test_dns_resolution(net):
    """Test DNS resolution with a few queries"""
    
    print("\n" + "="*70)
    print("Testing DNS Resolution")
    print("="*70)
    
    test_domains = ['google.com', 'facebook.com', 'github.com']
    
    h1 = net.get('h1')
    
    for domain in test_domains:
        print(f"\n  Testing: {domain}")
        result = h1.cmd(f'dig +short {domain} @10.0.0.5 | head -1')
        if result.strip():
            print(f"  [OK] Resolved: {result.strip()}")
        else:
            print(f"  [WAITING] No response (check logs)")
        time.sleep(1)
    
    print("\n" + "="*70)


def cleanup_private_mounts(net):
    """Cleanup private /etc/resolv.conf mounts"""
    
    print("\n  Cleaning up private mounts...")
    
    for host_name in ['h1', 'h2', 'h3', 'h4', 'dns']:
        try:
            host = net.get(host_name)
            if host:
                host.cmd('umount /etc/resolv.conf 2>/dev/null || true')
                host.cmd(f'rm -rf /tmp/mininet_{host_name}_etc 2>/dev/null || true')
        except:
            pass


def main():
    """Setup network and open CLI"""
    
    print("\n" + "="*70)
    print("PART C: Custom DNS Resolver Configuration")
    print("="*70)
    print("\nFeatures:")
    print("  - Iterative DNS resolution (Root -> TLD -> Authoritative)")
    print("  - Detailed logging of all DNS queries")
    print("  - DNS caching for performance")
    print("  - Full query path tracking")
    print("  - Isolated /etc/resolv.conf per host (won't affect VM)")
    print("\nNetwork:")
    print("  - Hosts: h1, h2, h3, h4")
    print("  - DNS Server: 10.0.0.5 (custom iterative resolver)")
    print("  - NAT: 10.0.0.254")
    print("="*70)
    
    
    # Setup network
    setLogLevel('info')
    topo = TopologyWithNAT()
    net = Mininet(topo=topo, link=TCLink,
                  controller=lambda name: OVSController(name, ip='127.0.0.1', port=6633))
    
    try:
        net.start()
        
        info("\n*** Configuring NAT\n")
        nat = net.get('nat0')
        nat.configDefault()
        
        print("\nWaiting for network to stabilize...")
        time.sleep(3)
        
        # Setup private /etc/resolv.conf for each host
        setup_private_resolv_conf(net)
        
        # Start custom DNS server
        dns_host = net.get('dns')
        if not start_custom_dns_server(dns_host):
            print("\n[WARNING] Continuing without DNS server...")
        else:
            # Configure hosts to use custom DNS
            configure_hosts(net)
            
            # Run quick tests
            test_dns_resolution(net)
        
        print("\n" + "="*70)
        print("Network Ready - Opening Mininet CLI")
        print("="*70)
        print("\nUseful Commands:")
        print("  mininet> h1 dig google.com")
        print("  mininet> h1 nslookup facebook.com 10.0.0.5")
        print("  mininet> h1 cat /etc/resolv.conf")
        print("  mininet> dns cat /tmp/dns_resolver.log")
        print("  mininet> dns tail -f /tmp/dns_server.log")
        print("  mininet> dns cat /tmp/dns_queries.json | python3 -m json.tool")
        print("\nView Statistics:")
        print("  mininet> dns cat /tmp/dns_queries.json | grep statistics -A 10")
        
        print("="*70 + "\n")
        
        # Open CLI
        CLI(net)
        
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\nCleaning up...")
        
        # Kill DNS server
        try:
            dns_host = net.get('dns')
            if dns_host:
                print("  Stopping DNS server...")
                dns_host.cmd('pkill -f custom_dns_server.py')
                time.sleep(1)
        except:
            pass
        
        # Cleanup private mounts
        cleanup_private_mounts(net)
        
        net.stop()
        
        # Verify VM DNS is restored
        print("\n  Verifying VM DNS configuration...")
        with open('/etc/resolv.conf', 'r') as f:
            vm_dns = f.read()
            if '8.8.8.8' in vm_dns or '10.0.2.3' in vm_dns:
                print("  [OK] VM DNS is unchanged (still using default)")
            else:
                print("  [WARNING] VM DNS may have changed. Restore with:")
                print("      echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf")
        
        print("\n[OK] Done!\n")


if __name__ == '__main__':
    main()