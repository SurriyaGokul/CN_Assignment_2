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
import json
from datetime import datetime

# Add resolver directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'resolver'))

try:
    from scapy.all import DNS, DNSQR ,PcapReader
except ImportError:
    print("Error: scapy is required. Install it with: pip install scapy")
    sys.exit(1)


class TopologyWithNAT(Topo):
    def build(self):
        # Adding switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        # Adding hosts with default route pointing to NAT
        h1 = self.addHost('h1', ip='10.0.0.1/24', defaultRoute='via 10.0.0.254')
        h2 = self.addHost('h2', ip='10.0.0.2/24', defaultRoute='via 10.0.0.254')
        h3 = self.addHost('h3', ip='10.0.0.3/24', defaultRoute='via 10.0.0.254')
        h4 = self.addHost('h4', ip='10.0.0.4/24', defaultRoute='via 10.0.0.254')
        dns = self.addHost('dns', ip='10.0.0.5/24', defaultRoute='via 10.0.0.254')
        
        # Add NAT node
        nat = self.addNode('nat0', cls=NAT, ip='10.0.0.254/24', 
                          subnet='10.0.0.0/24', inNamespace=False)

        # Adding links with bandwidth and delay
        self.addLink(h1, s1, cls=TCLink, bw=100, delay='2ms')
        self.addLink(h2, s2, cls=TCLink, bw=100, delay='2ms')
        self.addLink(h3, s3, cls=TCLink, bw=100, delay='2ms')
        self.addLink(h4, s4, cls=TCLink, bw=100, delay='2ms')
        self.addLink(dns, s2, cls=TCLink, bw=100, delay='1ms')
        
        # Connect NAT to switch s2 (central switch)
        self.addLink(nat, s2)

        # Adding switch interconnections
        self.addLink(s1, s2, cls=TCLink, bw=100, delay='5ms')
        self.addLink(s2, s3, cls=TCLink, bw=100, delay='8ms')
        self.addLink(s3, s4, cls=TCLink, bw=100, delay='10ms')


def extract_domains_from_pcap(pcap_file):
    domains = set()
    
    if not os.path.exists(pcap_file):
        print(f"Warning: PCAP file not found: {pcap_file}")
        return []
    
    try:
        print(f"Reading PCAP file in stream mode: {pcap_file}...", end=' ', flush=True)
        start_time = time.time()
        packet_count = 0
        dns_packet_count = 0
        
        # Use PcapReader for stream mode (doesn't load all packets into memory at once)
        with PcapReader(pcap_file) as pcap_reader:
            for packet in pcap_reader:
                packet_count += 1
                
                # Show progress every 100k packets
                if packet_count % 100000 == 0:
                    print(f"\n  [{packet_count//1000}k packets processed, {len(domains)} domains found]", end=' ', flush=True)
            
                # Process DNS queries only
                try:
                    if DNS in packet and packet.haslayer(DNS):
                        dns_layer = packet[DNS]
                        # Only process DNS queries (qr=0 means query, qr=1 means response)
                        if dns_layer.qr == 0 and dns_layer.qd:
                            dns_packet_count += 1
                            query = dns_layer.qd
                            
                            if hasattr(query, 'qname'):
                                qname = query.qname
                                if isinstance(qname, bytes):
                                    domain = qname.decode('utf-8', errors='ignore').strip('.')
                                else:
                                    domain = str(qname).strip('.')
                                
                                # Add valid domain names only
                                if domain and domain != '' and '.' in domain:
                                    domains.add(domain.lower())  # Normalize to lowercase
                except:
                    # Skip packets that can't be parsed
                    continue
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        print(f"\n  Processed {packet_count:,} packets ({dns_packet_count:,} DNS queries) in {processing_time:.2f}s")
        print(f"  Extracted {len(domains)} unique domains")
        
        # Return sorted list
        return sorted(list(domains))
        
    except Exception as e:
        print(f"\nError reading PCAP file {pcap_file}: {e}")
        import traceback
        traceback.print_exc()
        return []


def resolve_domain_on_host(host, domain, dns_server='8.8.8.8', timeout=5):

    result = {
        'domain': domain,
        'success': False,
        'latency': None,
        'ip_address': None,
        'error': None,
        'bytes_transferred': 0
    }
    
    # Use nslookup for DNS resolution with timing
    cmd = f"timeout {timeout} nslookup {domain} {dns_server}"
    
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
        elif "network unreachable" in output.lower():
            result['success'] = False
            result['error'] = "Network unreachable"
        elif "timed out" in output.lower() or "timeout" in output.lower():
            result['success'] = False
            result['error'] = "Query timeout"
        else:
        
            lines = output.split('\n')
            found_answer_section = False
            
            for i, line in enumerate(lines):
                # Look for "Non-authoritative answer:" or the domain name
                if 'non-authoritative answer' in line.lower() or f'name:\t{domain}' in line.lower():
                    found_answer_section = True
                    continue
                
                # After finding the answer section, look for Address:
                if found_answer_section and 'address:' in line.lower():
                    parts = line.split('Address:')
                    if len(parts) > 1:
                        ip = parts[1].strip().split('#')[0].strip()
                        # Validate it's not the DNS server IP and it's a valid IP format
                        if ip and ip != dns_server and '.' in ip and not ip.startswith('127.'):
                            # Additional validation: check if it looks like an IPv4 address
                            ip_parts = ip.split('.')
                            if len(ip_parts) == 4:
                                try:
                                    # Check if all parts are valid numbers
                                    if all(0 <= int(part) <= 255 for part in ip_parts):
                                        result['ip_address'] = ip
                                        result['success'] = True
                                        break
                                except ValueError:
                                    continue
            
            # Alternative parsing: look for "Name:" followed by "Address:"
            if not result['success']:
                for i, line in enumerate(lines):
                    if 'name:' in line.lower() and domain.lower() in line.lower():
                        # Check the next few lines for Address:
                        for j in range(i+1, min(i+5, len(lines))):
                            next_line = lines[j]
                            if 'address:' in next_line.lower():
                                parts = next_line.split('Address:')
                                if len(parts) > 1:
                                    ip = parts[1].strip().split('#')[0].strip()
                                    if ip and ip != dns_server and '.' in ip:
                                        ip_parts = ip.split('.')
                                        if len(ip_parts) == 4:
                                            try:
                                                if all(0 <= int(part) <= 255 for part in ip_parts):
                                                    result['ip_address'] = ip
                                                    result['success'] = True
                                                    break
                                            except ValueError:
                                                continue
                        if result['success']:
                            break
            
            # Check for IPv6 addresses if no IPv4 found
            if not result['success']:
                for line in lines:
                    if 'address:' in line.lower() and '::' in line:
                        # Extract IPv6 address
                        parts = line.split('Address:')
                        if len(parts) > 1:
                            ipv6 = parts[1].strip().split('#')[0].strip()
                            if '::' in ipv6:
                                result['success'] = True
                                result['ip_address'] = ipv6
                                break
            
            # Still no success? Mark as parsing error
            if not result['success']:
                result['error'] = "Could not parse IP address from response"
        
    except Exception as e:
        end_time = time.time()
        result['latency'] = (end_time - start_time) * 1000
        result['error'] = str(e)
        result['success'] = False
    
    return result


def test_dns_resolution_for_host(net, host_name, pcap_file, dns_server='8.8.8.8'):

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
        
        print("\nTesting internal connectivity...")
        net.pingAll()
        
        # Wait for routing to settle
        time.sleep(2)
        
        # Test internet connectivity
        print("\n*** Testing internet connectivity ***")
        h1 = net.get('h1')
        
        print("  Testing ping to 8.8.8.8...")
        result = h1.cmd('ping -c 3 -W 3 8.8.8.8')
        if 'bytes from 8.8.8.8' in result or '3 received' in result:
            print("  Internet connectivity working!")
        else:
            print(" Ping failed. Output:")
            print("  " + result.replace('\n', '\n  ')[:400])
        
        # Configure DNS for each host
        print(f"\nConfiguring DNS server ({dns_server}) for all hosts...")
        for host_name in ['h1', 'h2', 'h3', 'h4']:
            host = net.get(host_name)
            host.cmd(f'echo "nameserver {dns_server}" > /etc/resolv.conf')
            print(f"  {host_name}: DNS configured")
        
        # Test DNS resolution
        print("\n*** Testing DNS resolution ***")
        test_result = h1.cmd('nslookup google.com ' + dns_server)
        if 'Address:' in test_result and 'google.com' in test_result.lower():
            print("  DNS resolution working!")
        else:
            print("   DNS test output:")
            print("  " + test_result.replace('\n', '\n  ')[:300])
        
        # PCAP files for each host
        pcap_files = {
            'h1': 'data/PCAP_1_H1.pcap',
            'h2': 'data/PCAP_2_H2.pcap',
            'h3': 'data/PCAP_3_H3.pcap',
            'h4': 'data/PCAP_4_H4.pcap'
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