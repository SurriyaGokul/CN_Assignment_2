#!/usr/bin/env python3
"""
Part B: DNS Resolution Testing with Default Host Resolver
Uses the default host resolver to resolve URLs from PCAP files in the simulated topology.
Records average lookup latency, throughput, success/failure metrics per host.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSController
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink
import sys
import os
import time
import json
from datetime import datetime

# Add resolver directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'resolver'))

try:
    from scapy.all import rdpcap, DNS, DNSQR
except ImportError:
    print("Error: scapy is required. Install it with: pip install scapy")
    sys.exit(1)


class Topology(Topo):
    """Network topology with 4 hosts and 1 DNS server"""
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


def enable_nat_internet_access(net):
    """
    Enable NAT for Mininet hosts to access the internet
    This allows hosts to reach external DNS servers like 8.8.8.8
    """
    print("\n*** Configuring NAT for internet access ***")
    
    # Get the root namespace interface (typically eth0 or similar)
    root_intf = None
    import subprocess
    try:
        # Find the default route interface
        result = subprocess.check_output("ip route | grep default | awk '{print $5}'", shell=True).decode().strip()
        if result:
            root_intf = result
            print(f"  Using host interface: {root_intf}")
    except:
        # Fallback to common interface names
        for intf in ['eth0', 'ens33', 'enp0s3', 'wlan0']:
            try:
                subprocess.check_output(f"ip link show {intf}", shell=True, stderr=subprocess.DEVNULL)
                root_intf = intf
                print(f"  Using host interface: {root_intf}")
                break
            except:
                continue
    
    if not root_intf:
        print("  ⚠️  Could not detect host interface, using eth0")
        root_intf = 'eth0'
    
    # Enable IP forwarding
    print("  Enabling IP forwarding...")
    os.system('sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1')
    
    # Configure NAT using iptables
    print("  Configuring NAT rules...")
    
    # Clear existing NAT rules
    os.system('iptables -t nat -F')
    os.system('iptables -t nat -X')
    
    # Add NAT rule for Mininet network (10.0.0.0/24)
    os.system(f'iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o {root_intf} -j MASQUERADE')
    
    # Configure default gateway for all hosts
    print("  Setting default gateway for hosts...")
    for host_name in ['h1', 'h2', 'h3', 'h4', 'dns']:
        host = net.get(host_name)
        # Add default route through one of the switches (use root namespace)
        host.cmd(f'ip route add default via 10.0.0.254 dev {host_name}-eth0 2>/dev/null || true')
        # Also try direct route to internet gateway
        host.cmd(f'route add default gw 10.0.0.254 2>/dev/null || true')
    
    print("  ✅ NAT configuration complete")
    
    return True


def extract_domains_from_pcap(pcap_file):
    """
    Extract unique domain names from PCAP file
    
    Args:
        pcap_file (str): Path to PCAP file
        
    Returns:
        list: List of unique domain names
    """
    domains = set()
    
    if not os.path.exists(pcap_file):
        print(f"Warning: PCAP file not found: {pcap_file}")
        return []
    
    try:
        packets = rdpcap(pcap_file)
        print(f"Loaded {len(packets)} packets from {pcap_file}")
        
        for packet in packets:
            if DNS in packet and packet[DNS].qd:
                dns_layer = packet[DNS]
                # Only process DNS queries (qr=0)
                if dns_layer.qr == 0:
                    try:
                        query = dns_layer.qd
                        if hasattr(query, 'qname'):
                            qname = query.qname
                            if isinstance(qname, bytes):
                                domain = qname.decode('utf-8', errors='ignore').strip('.')
                            else:
                                domain = str(qname).strip('.')
                            
                            if domain and domain != '':
                                domains.add(domain)
                    except Exception as e:
                        print(f"Error parsing DNS query: {e}")
                        continue
        
        print(f"Extracted {len(domains)} unique domains from {pcap_file}")
        return sorted(list(domains))
        
    except Exception as e:
        print(f"Error reading PCAP file {pcap_file}: {e}")
        return []


def resolve_domain_on_host(host, domain, dns_server='8.8.8.8'):
    """
    Resolve a domain using the default host resolver (getent or nslookup)
    
    Args:
        host: Mininet host object
        domain (str): Domain name to resolve
        dns_server (str): DNS server IP (optional)
        
    Returns:
        dict: Resolution result with latency, success status, and IP
    """
    result = {
        'domain': domain,
        'success': False,
        'latency': None,
        'ip_address': None,
        'error': None,
        'bytes_transferred': 0
    }
    
    # Use nslookup for DNS resolution with timing
    # nslookup is more portable and provides better control
    cmd = f"nslookup {domain} {dns_server}"
    
    start_time = time.time()
    try:
        output = host.cmd(cmd)
        end_time = time.time()
        
        latency = (end_time - start_time) * 1000  # Convert to milliseconds
        result['latency'] = latency
        result['bytes_transferred'] = len(output)
        
        # Parse nslookup output to check if resolution succeeded
        if "server can't find" in output.lower() or "nxdomain" in output.lower():
            result['success'] = False
            result['error'] = "Domain not found (NXDOMAIN)"
        elif "connection timed out" in output.lower() or "no servers could be reached" in output.lower():
            result['success'] = False
            result['error'] = "DNS server unreachable"
        else:
            # Try to extract IP address from output
            lines = output.split('\n')
            for i, line in enumerate(lines):
                if 'Address:' in line and i > 0:  # Skip the DNS server address
                    parts = line.split('Address:')
                    if len(parts) > 1:
                        ip = parts[1].strip().split('#')[0].strip()
                        if ip and not ip.startswith('127.') and '.' in ip:
                            result['ip_address'] = ip
                            result['success'] = True
                            break
            
            # If no IP found but no error, mark as failed
            if not result['success']:
                result['error'] = "Could not parse IP address from response"
        
    except Exception as e:
        end_time = time.time()
        result['latency'] = (end_time - start_time) * 1000
        result['error'] = str(e)
        result['success'] = False
    
    return result


def test_dns_resolution_for_host(net, host_name, pcap_file, dns_server='8.8.8.8'):
    """
    Test DNS resolution for a specific host using domains from its PCAP file
    
    Args:
        net: Mininet network object
        host_name (str): Name of the host (e.g., 'h1')
        pcap_file (str): Path to PCAP file for this host
        dns_server (str): DNS server IP to use
        
    Returns:
        dict: Statistics for this host
    """
    print(f"\n{'='*70}")
    print(f"Testing DNS resolution for {host_name.upper()}")
    print(f"PCAP file: {pcap_file}")
    print(f"DNS Server: {dns_server}")
    print(f"{'='*70}")
    
    host = net.get(host_name)
    domains = extract_domains_from_pcap(pcap_file)
    
    if not domains:
        print(f"No domains found in {pcap_file}")
        return {
            'host': host_name,
            'pcap_file': pcap_file,
            'total_queries': 0,
            'successful_queries': 0,
            'failed_queries': 0,
            'average_latency_ms': 0,
            'average_throughput_bps': 0,
            'domains_tested': [],
            'results': []
        }
    
    print(f"\nResolving {len(domains)} unique domains...")
    
    results = []
    successful = 0
    failed = 0
    total_latency = 0
    total_bytes = 0
    total_time = 0
    
    for i, domain in enumerate(domains, 1):
        print(f"[{i}/{len(domains)}] Resolving {domain}...", end=' ')
        
        result = resolve_domain_on_host(host, domain, dns_server)
        results.append(result)
        
        if result['success']:
            successful += 1
            total_latency += result['latency']
            total_bytes += result['bytes_transferred']
            total_time += result['latency'] / 1000  # Convert to seconds
            print(f"✓ Success (IP: {result['ip_address']}, Latency: {result['latency']:.2f} ms)")
        else:
            failed += 1
            print(f"✗ Failed ({result['error']})")
    
    # Calculate statistics
    avg_latency = total_latency / successful if successful > 0 else 0
    # Throughput = (total bytes * 8) / total time in seconds
    avg_throughput = (total_bytes * 8) / total_time if total_time > 0 else 0
    
    stats = {
        'host': host_name,
        'pcap_file': pcap_file,
        'total_queries': len(domains),
        'successful_queries': successful,
        'failed_queries': failed,
        'average_latency_ms': round(avg_latency, 2),
        'average_throughput_bps': round(avg_throughput, 2),
        'domains_tested': domains,
        'results': results
    }
    
    print(f"\n{'-'*70}")
    print(f"Statistics for {host_name.upper()}:")
    print(f"  Total Queries: {stats['total_queries']}")
    print(f"  Successful: {stats['successful_queries']}")
    print(f"  Failed: {stats['failed_queries']}")
    print(f"  Success Rate: {(successful/len(domains)*100):.1f}%")
    print(f"  Average Latency: {stats['average_latency_ms']:.2f} ms")
    print(f"  Average Throughput: {stats['average_throughput_bps']:.2f} bps")
    print(f"{'-'*70}")
    
    return stats


def run_part_b_tests(dns_server='8.8.8.8'):
    """
    Run Part B DNS resolution tests for all hosts
    
    Args:
        dns_server (str): DNS server IP to use for resolution
    """
    print("\n" + "="*70)
    print("PART B: DNS Resolution Testing with Default Host Resolver")
    print("="*70)
    
    # Setup topology
    setLogLevel('info')
    topo = Topology()
    net = Mininet(topo=topo, link=TCLink, 
                  controller=lambda name: OVSController(name, ip='127.0.0.1', port=6633))
    
    try:
        net.start()
        
        print("\nWaiting for network to stabilize...")
        time.sleep(2)
        
        print("\nTesting connectivity...")
        net.pingAll()
        
        # Enable NAT for internet access
        enable_nat_internet_access(net)
        
        # Test internet connectivity from h1
        print("\n*** Testing internet connectivity ***")
        h1 = net.get('h1')
        result = h1.cmd('ping -c 2 -W 2 8.8.8.8')
        if '2 received' in result or '2 packets received' in result:
            print("  ✅ Internet connectivity working!")
        else:
            print("  ⚠️  Internet connectivity may have issues")
            print(f"  Ping result: {result[:200]}")
        
        # Configure DNS for each host (use public DNS)
        print(f"\nConfiguring DNS server ({dns_server}) for all hosts...")
        for host_name in ['h1', 'h2', 'h3', 'h4']:
            host = net.get(host_name)
            # Configure resolv.conf to use specified DNS server
            host.cmd(f'echo "nameserver {dns_server}" > /etc/resolv.conf')
        
        # PCAP files for each host
        pcap_files = {
            'h1': 'pcap_files/PCAP_1_H1.pcap',
            'h2': 'pcap_files/PCAP_2_H2.pcap',
            'h3': 'pcap_files/PCAP_3_H3.pcap',
            'h4': 'pcap_files/PCAP_4_H4.pcap'
        }
        
        # Test DNS resolution for each host
        all_stats = []
        for host_name in ['h1', 'h2', 'h3', 'h4']:
            pcap_file = pcap_files[host_name]
            stats = test_dns_resolution_for_host(net, host_name, pcap_file, dns_server)
            all_stats.append(stats)
            time.sleep(1)  # Brief pause between hosts
        
        # Save results to file
        output_file = 'part_b_results.json'
        with open(output_file, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'dns_server': dns_server,
                'results': all_stats
            }, f, indent=2)
        
        print(f"\n{'='*70}")
        print(f"SUMMARY OF ALL HOSTS")
        print(f"{'='*70}")
        
        # Print summary table
        print(f"\n{'Host':<8} {'Total':<8} {'Success':<10} {'Failed':<8} {'Avg Latency':<15} {'Avg Throughput':<20}")
        print(f"{'-'*80}")
        for stats in all_stats:
            print(f"{stats['host']:<8} {stats['total_queries']:<8} "
                  f"{stats['successful_queries']:<10} {stats['failed_queries']:<8} "
                  f"{stats['average_latency_ms']:<15.2f} {stats['average_throughput_bps']:<20.2f}")
        
        print(f"\n{'='*70}")
        print(f"Results saved to: {output_file}")
        print(f"{'='*70}")
        
        # Optional: Open CLI for manual testing
        print("\nOpening Mininet CLI for manual testing (type 'exit' to quit)...")
        CLI(net)
        
    except Exception as e:
        print(f"\nError during testing: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\nStopping network...")
        net.stop()


if __name__ == '__main__':
    # Check if DNS server is provided as argument
    dns_server = '8.8.8.8'  # Default to Google DNS
    
    if len(sys.argv) > 1:
        dns_server = sys.argv[1]
    
    print(f"Using DNS server: {dns_server}")
    run_part_b_tests(dns_server)
