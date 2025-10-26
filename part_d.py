#!/usr/bin/env python3
"""
Part D: DNS Resolution with Custom Resolver + Comparison with Part B
Resolves domains from PCAPs using custom DNS and generates comparison + visualizations
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
import json
from datetime import datetime
from scapy.all import DNS, DNSQR, PcapReader
import subprocess
import re


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
    """Setup isolated /etc/resolv.conf for each host (from part_c.py)"""
    
    print("\n" + "="*70)
    print("Setting Up Isolated DNS Configuration (VM won't be affected)")
    print("="*70)
    
    for host_name in ['h1', 'h2', 'h3', 'h4', 'dns']:
        host = net.get(host_name)
        
        # Create private directory for this host
        private_dir = f'/tmp/mininet_{host_name}_etc'
        host.cmd(f'mkdir -p {private_dir}')
        
        # Create a private resolv.conf
        host.cmd(f'echo "# Mininet host {host_name}" > {private_dir}/resolv.conf')
        
        # DNS host uses 8.8.8.8 for upstream, others use 10.0.0.5
        if host_name == 'dns':
            host.cmd(f'echo "nameserver 8.8.8.8" >> {private_dir}/resolv.conf')
        else:
            host.cmd(f'echo "nameserver 10.0.0.5" >> {private_dir}/resolv.conf')
        
        # Mount it over /etc/resolv.conf
        host.cmd(f'mount --bind {private_dir}/resolv.conf /etc/resolv.conf 2>/dev/null || true')
        
        # Verify
        result = host.cmd('cat /etc/resolv.conf').strip()
        if host_name == 'dns':
            if '8.8.8.8' in result:
                print(f"  [OK] {host_name}: DNS = 8.8.8.8 (upstream)")
            else:
                print(f"  [WARNING] {host_name}: DNS setup may have failed")
        else:
            if '10.0.0.5' in result:
                print(f"  [OK] {host_name}: DNS = 10.0.0.5 (custom)")
            else:
                print(f"  [WARNING] {host_name}: DNS setup may have failed")
    
    print("="*70)


def cleanup_private_mounts(net):
    """Cleanup private /etc/resolv.conf mounts (from part_c.py)"""
    
    print("\n  Cleaning up private mounts...")
    
    for host_name in ['h1', 'h2', 'h3', 'h4', 'dns']:
        try:
            host = net.get(host_name)
            if host:
                host.cmd('umount /etc/resolv.conf 2>/dev/null || true')
                host.cmd(f'rm -rf /tmp/mininet_{host_name}_etc 2>/dev/null || true')
        except:
            pass


def extract_domains_from_pcap(pcap_file, max_domains=None):
    """Extract unique domains from PCAP file (same as Part B)"""
    domains = set()
    
    if not os.path.exists(pcap_file):
        print(f"Warning: PCAP file not found: {pcap_file}")
        return []
    
    try:
        print(f"  Reading PCAP: {pcap_file}...", end=' ', flush=True)
        start_time = time.time()
        packet_count = 0
        
        with PcapReader(pcap_file) as pcap_reader:
            for packet in pcap_reader:
                packet_count += 1
                
                if packet_count % 100000 == 0:
                    print(f"\n    [{packet_count//1000}k packets, {len(domains)} domains]", end=' ', flush=True)
            
                try:
                    if DNS in packet and packet.haslayer(DNS):
                        dns_layer = packet[DNS]
                        if dns_layer.qr == 0 and dns_layer.qd:
                            query = dns_layer.qd
                            if hasattr(query, 'qname'):
                                qname = query.qname
                                if isinstance(qname, bytes):
                                    domain = qname.decode('utf-8', errors='ignore').strip('.')
                                else:
                                    domain = str(qname).strip('.')
                                
                                if domain and '.' in domain:
                                    domains.add(domain.lower())
                except:
                    continue
        
        processing_time = time.time() - start_time
        print(f"\n    ✅ Processed {packet_count:,} packets in {processing_time:.2f}s")
        print(f"    ✅ Found {len(domains)} unique domains")
        
        domain_list = sorted(list(domains))
        if max_domains:
            return domain_list[:max_domains]
        return domain_list
        
    except Exception as e:
        print(f"\n    ❌ Error: {e}")
        return []


def resolve_domain_on_host(host, domain, dns_server, timeout=5):
    """Resolve domain using dig (more reliable IP parsing than nslookup)"""
    
    result = {
        'domain': domain,
        'success': False,
        'latency': None,
        'ip_address': None,
        'error': None,
        'bytes_transferred': 0
    }
    
    # Use dig with +short for cleaner output
    cmd = f"timeout {timeout} dig +short {domain} @{dns_server}"
    
    start_time = time.time()
    try:
        output = host.cmd(cmd)
        end_time = time.time()
        
        latency = (end_time - start_time) * 1000  # ms
        result['latency'] = latency
        result['bytes_transferred'] = len(output)
        
        # Check for timeout
        if not output.strip():
            result['error'] = "Timeout/No response"
            return result
        
        # Parse dig output - first line is usually the IP
        lines = output.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            
            # IPv4 pattern
            ipv4_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
            if re.match(ipv4_pattern, line):
                # Validate IP
                parts = line.split('.')
                try:
                    if all(0 <= int(part) <= 255 for part in parts):
                        result['ip_address'] = line
                        result['success'] = True
                        return result
                except ValueError:
                    continue
            
            # IPv6 pattern
            ipv6_pattern = r'^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
            if re.match(ipv6_pattern, line) and '::' in line and line != '::1':
                result['ip_address'] = line
                result['success'] = True
                return result
        
        # If we get here, no valid IP was found
        if 'NXDOMAIN' in output or 'SERVFAIL' in output:
            result['error'] = "NXDOMAIN"
        else:
            result['error'] = "Could not parse IP"
        
    except Exception as e:
        result['error'] = str(e)
    
    return result


def resolve_domains_from_pcap(host, host_name, pcap_file, dns_server):
    """Resolve all domains from PCAP using specified DNS server"""
    
    print(f"\n{'='*70}")
    print(f"Resolving domains from {os.path.basename(pcap_file)} on {host_name.upper()}")
    print(f"DNS Server: {dns_server}")
    print(f"{'='*70}")
    
    # Extract domains
    domains = extract_domains_from_pcap(pcap_file)
    
    if not domains:
        print("  ❌ No domains found")
        return None
    
    print(f"\n  🔄 Resolving {len(domains)} domains using dig...\n")
    
    results = []
    successful = 0
    failed = 0
    total_latency = 0
    total_bytes = 0
    total_time = 0
    
    for i, domain in enumerate(domains, 1):
        if i % 10 == 1:
            print(f"\n  Progress: {i}/{len(domains)}")
        
        result = resolve_domain_on_host(host, domain, dns_server)
        results.append(result)
        
        status_icon = "✅" if result['success'] else "❌"
        if result['success']:
            info_msg = f"IP: {result['ip_address']}"
        else:
            info_msg = result.get('error', 'Unknown error')
        
        print(f"    [{i:3d}] {domain:50s} {status_icon} {info_msg}")
        
        if result['success']:
            successful += 1
            total_latency += result['latency']
            total_bytes += result['bytes_transferred']
            total_time += result['latency'] / 1000
        else:
            failed += 1
    
    # Calculate statistics
    avg_latency = total_latency / successful if successful > 0 else 0
    avg_throughput = (total_bytes * 8) / total_time if total_time > 0 else 0
    
    stats = {
        'host': host_name,
        'pcap_file': os.path.basename(pcap_file),
        'dns_server': dns_server,
        'total_queries': len(domains),
        'successful_queries': successful,
        'failed_queries': failed,
        'success_rate': (successful / len(domains) * 100) if domains else 0,
        'average_latency_ms': round(avg_latency, 2),
        'average_throughput_bps': round(avg_throughput, 2),
        'domains_tested': domains,
        'results': results
    }
    
    print(f"\n  📊 Statistics:")
    print(f"     Total: {stats['total_queries']}")
    print(f"     Success: {successful} ({stats['success_rate']:.1f}%)")
    print(f"     Failed: {failed}")
    print(f"     Avg Latency: {stats['average_latency_ms']:.2f} ms")
    
    return stats


def compare_part_b_and_d(part_b_file, part_d_results, output_dir='./results'):
    """Compare Part B (8.8.8.8) vs Part D (10.0.0.5) results"""
    
    print(f"\n{'='*70}")
    print("COMPARISON: Part B (8.8.8.8) vs Part D (10.0.0.5)")
    print(f"{'='*70}")
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Load Part B results
    try:
        with open(part_b_file, 'r') as f:
            part_b_data = json.load(f)
        part_b_results = part_b_data.get('results', [])
        print(f"  ✅ Loaded Part B results: {len(part_b_results)} hosts")
    except Exception as e:
        print(f"  ⚠️  Could not load Part B results: {e}")
        print(f"  ℹ️  Continuing without comparison...")
        return
    
    # Comparison data
    comparison = {
        'timestamp': datetime.now().isoformat(),
        'part_b_dns': '8.8.8.8',
        'part_d_dns': '10.0.0.5',
        'comparison': []
    }
    
    # Compare each host
    for part_d_stat in part_d_results:
        host_name = part_d_stat['host']
        
        # Find matching Part B result
        part_b_stat = next((r for r in part_b_results if r['host'] == host_name), None)
        
        if not part_b_stat:
            print(f"  ⚠️  No Part B data for {host_name}")
            continue
        
        comp = {
            'host': host_name,
            'part_b': {
                'total_queries': part_b_stat.get('total_queries', 0),
                'successful': part_b_stat.get('successful_queries', 0),
                'avg_latency_ms': part_b_stat.get('average_latency_ms', 0),
                'success_rate': part_b_stat.get('successful_queries', 0) / part_b_stat.get('total_queries', 1) * 100
            },
            'part_d': {
                'total_queries': part_d_stat.get('total_queries', 0),
                'successful': part_d_stat.get('successful_queries', 0),
                'avg_latency_ms': part_d_stat.get('average_latency_ms', 0),
                'success_rate': part_d_stat.get('success_rate', 0)
            }
        }
        
        # Calculate differences
        comp['latency_diff_ms'] = comp['part_d']['avg_latency_ms'] - comp['part_b']['avg_latency_ms']
        comp['latency_diff_percent'] = (comp['latency_diff_ms'] / comp['part_b']['avg_latency_ms'] * 100) if comp['part_b']['avg_latency_ms'] > 0 else 0
        
        comparison['comparison'].append(comp)
        
        # Print comparison
        print(f"\n  {host_name.upper()}:")
        print(f"    Part B (8.8.8.8):     {comp['part_b']['successful']}/{comp['part_b']['total_queries']} success, "
              f"{comp['part_b']['avg_latency_ms']:.2f}ms avg latency")
        print(f"    Part D (10.0.0.5):    {comp['part_d']['successful']}/{comp['part_d']['total_queries']} success, "
              f"{comp['part_d']['avg_latency_ms']:.2f}ms avg latency")
        print(f"    Difference:           {comp['latency_diff_ms']:+.2f}ms ({comp['latency_diff_percent']:+.1f}%)")
    
    # Save comparison
    json_file = os.path.join(output_dir, 'part_b_d_comparison.json')
    with open(json_file, 'w') as f:
        json.dump(comparison, f, indent=2)
    print(f"\n  ✅ Comparison saved to: {json_file}")
    
    # Save CSV
    csv_file = os.path.join(output_dir, 'part_b_d_comparison.csv')
    with open(csv_file, 'w') as f:
        f.write("Host,Part_B_Success,Part_B_Latency_ms,Part_D_Success,Part_D_Latency_ms,Diff_ms,Diff_percent\n")
        for comp in comparison['comparison']:
            f.write(f"{comp['host']},{comp['part_b']['successful']},"
                   f"{comp['part_b']['avg_latency_ms']:.2f},{comp['part_d']['successful']},"
                   f"{comp['part_d']['avg_latency_ms']:.2f},{comp['latency_diff_ms']:.2f},"
                   f"{comp['latency_diff_percent']:.1f}\n")
    print(f"  ✅ CSV saved to: {csv_file}")


def generate_plots_for_h1(dns_log_file, output_dir='./plots'):
    """Generate required plots for H1 (first 10 URLs)"""
    
    print(f"\n{'='*70}")
    print("Generating Plots for H1 (First 10 Queries)")
    print(f"{'='*70}")
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Check if log file exists
    if not os.path.exists(dns_log_file):
        print(f"  ⚠️  DNS log file not found: {dns_log_file}")
        print(f"  ℹ️  Plots will not be generated")
        return
    
    # Run visualization script
    script_path = os.path.join(os.path.dirname(__file__), 'generate_visualizations.py')
    
    if os.path.exists(script_path):
        cmd = f"python3 {script_path} {dns_log_file} {output_dir}"
        print(f"  Running: {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("  ✅ Plots generated successfully!")
            if result.stdout:
                print(result.stdout)
        else:
            print(f"  ❌ Error generating plots:")
            if result.stderr:
                print(result.stderr)
    else:
        print(f"  ⚠️  Visualization script not found: {script_path}")
        print(f"  ℹ️  You can generate plots manually later")


def main():
    """Main function for Part D"""
    
    print("\n" + "="*70)
    print("PART D: DNS Resolution with Custom Resolver")
    print("="*70)
    print("\n  📋 Tasks:")
    print("  1. Start custom DNS server (10.0.0.5)")
    print("  2. Resolve domains from PCAPs")
    print("  3. Compare with Part B (8.8.8.8)")
    print("  4. Generate plots for H1")
    print("\n  🔒 Isolated DNS (VM won't be affected)")
    print("="*70)
    
    input("\nPress Enter to start Part D...\n")
    
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
        
        print("\n⏳ Network stabilizing...")
        time.sleep(3)
        
        # Setup isolated /etc/resolv.conf (from part_c.py)
        setup_private_resolv_conf(net)
        
        # Start custom DNS server
        print(f"\n{'='*70}")
        print("STEP 1: Starting Custom DNS Server")
        print(f"{'='*70}")
        print("  📍 IP: 10.0.0.5:53")
        print("  📍 Mode: Iterative Resolution")
        
        dns_host = net.get('dns')
        
        # Install dependencies
        print("\n  📦 Installing dependencies...")
        dns_host.cmd('pip3 install -q dnspython 2>&1 | grep -v "already satisfied" || true')
        
        print("  📋 Setting up DNS server...")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        dns_script = os.path.join(script_dir, 'custom_dns_server.py')
        
        if not os.path.exists(dns_script):
            print(f"     ❌ custom_dns_server.py not found at {dns_script}")
            return
        
        # Start DNS server
        print("  🚀 Starting DNS server...")
        dns_host.cmd(f'python3 {dns_script} > /tmp/dns_server.log 2>&1 &')
        os.makedirs('./results', exist_ok=True)
        os.makedirs('./plots', exist_ok=True)
        time.sleep(4)
        
        # Verify
        result = dns_host.cmd('netstat -uln 2>/dev/null | grep :53 || ss -uln 2>/dev/null | grep :53')
        if ':53' in result:
            print("  ✅ DNS server RUNNING on port 53")
            print("     Logs: /tmp/dns_server.log, /tmp/dns_queries.json")
        else:
            print("  ⚠️  DNS server may not have started properly")
        
        # Verify VM DNS is unchanged
        print(f"\n{'='*70}")
        print("Verifying VM DNS Configuration")
        print(f"{'='*70}")
        with open('/etc/resolv.conf', 'r') as f:
            vm_dns = f.read()
            if '10.0.0.5' not in vm_dns:
                print("  ✅ VM DNS is unchanged (isolated from Mininet)")
            else:
                print("  ⚠️  VM DNS may have been modified!")
        
        # Resolve domains from PCAPs
        print(f"\n{'='*70}")
        print("STEP 2: DNS Resolution Tests")
        print(f"{'='*70}")
        
        pcap_files = {
            'h1': 'data/PCAP_1_H1.pcap',
            'h2': 'data/PCAP_2_H2.pcap',
            'h3': 'data/PCAP_3_H3.pcap',
            'h4': 'data/PCAP_4_H4.pcap'
        }
        
        part_d_results = []
        
        for host_name in ['h1', 'h2', 'h3', 'h4']:
            host = net.get(host_name)
            pcap_file = pcap_files[host_name]
            
            if not os.path.exists(pcap_file):
                print(f"\n  ⚠️  Skipping {host_name}: PCAP not found: {pcap_file}")
                continue
            
            stats = resolve_domains_from_pcap(host, host_name, pcap_file, '10.0.0.5')
            if stats:
                part_d_results.append(stats)
                
                # Save individual host results
                host_result_file = f'./results/part_d_{host_name}_results.json'
                with open(host_result_file, 'w') as f:
                    json.dump(stats, f, indent=2)
                print(f"  💾 Saved: {host_result_file}")
            
            time.sleep(2)
        
        # Save Part D results
        os.makedirs('./results', exist_ok=True)
        part_d_file = './results/part_d_results.json'
        with open(part_d_file, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'dns_server': '10.0.0.5',
                'results': part_d_results
            }, f, indent=2)
        print(f"\n  ✅ Part D results saved to: {part_d_file}")
        
        # Compare with Part B
        print(f"\n{'='*70}")
        print("STEP 3: Comparison with Part B")
        print(f"{'='*70}")
        compare_part_b_and_d('part_b_results.json', part_d_results)
        
        # Generate plots for H1
        print(f"\n{'='*70}")
        print("STEP 4: Generating Plots for H1")
        print(f"{'='*70}")
        generate_plots_for_h1('/tmp/dns_queries.json')
        
        print(f"\n{'='*70}")
        print("✅ PART D COMPLETE!")
        print(f"{'='*70}")
        print("\n📁 Generated Files:")
        print("  results/part_d_results.json - Combined results")
        print("  results/part_d_h1_results.json - H1 individual results")
        print("  results/part_d_h2_results.json - H2 individual results")
        print("  results/part_d_h3_results.json - H3 individual results")
        print("  results/part_d_h4_results.json - H4 individual results")
        print("  results/part_b_d_comparison.json - Comparison data")
        print("  results/part_b_d_comparison.csv - Comparison CSV")
        print("  plots/h1_latency_first_10_queries.png - Latency plot")
        print("  plots/h1_servers_visited_first_10_queries.png - Servers plot")
        print("\n📋 DNS Logs:")
        print("  /tmp/dns_queries.json - Detailed query logs")
        print("  /tmp/dns_resolver.log - Resolver logs")
        print("  /tmp/dns_server.log - Server logs")
        print(f"{'='*70}")
        
        # Open CLI for verification
        print("\n✨ Opening Mininet CLI for verification...")
        print("   Useful commands:")
        print("     mininet> h1 cat /etc/resolv.conf")
        print("     mininet> h1 dig google.com")
        print("     mininet> dns cat /tmp/dns_queries.json | python3 -m json.tool")
        print("   Type 'exit' to finish\n")
        CLI(net)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\n🧹 Cleaning up...")
        try:
            dns_host = net.get('dns')
            if dns_host:
                dns_host.cmd('pkill -f custom_dns_server.py')
                time.sleep(1)
        except:
            pass
        
        # Cleanup isolated mounts (from part_c.py)
        cleanup_private_mounts(net)
        
        net.stop()
        
        # Final verification
        print("\n  Verifying VM DNS after cleanup...")
        with open('/etc/resolv.conf', 'r') as f:
            vm_dns = f.read()
            if '10.0.0.5' not in vm_dns:
                print("  ✅ VM DNS is unchanged")
            else:
                print("  ⚠️  VM DNS was modified. Restore with:")
                print("      echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf")
        
        print("\n✅ Done!\n")


if __name__ == '__main__':
    main()