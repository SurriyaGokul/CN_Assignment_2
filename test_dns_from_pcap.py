#!/usr/bin/env python3
"""
Test DNS Resolution from PCAP Files in Mininet
Extracts domains from PCAP files and tests them using the custom DNS resolver

This script should be run INSIDE Mininet CLI after setup_custom_dns.py
Usage in Mininet CLI:
    h1 python3 test_dns_from_pcap.py PCAP_1_H1.pcap

Or run directly on a host:
    python3 test_dns_from_pcap.py <pcap_file>
"""

import sys
import os
import time
import json
import subprocess
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import rdpcap, DNS, DNSQR
except ImportError:
    print("Error: scapy is required. Install with: pip install scapy")
    sys.exit(1)


class PCAPDNSTester:
    """Test DNS resolution for domains from PCAP"""
    
    def __init__(self, pcap_file, dns_server='10.0.0.5', output_dir='./results'):
        self.pcap_file = pcap_file
        self.dns_server = dns_server
        self.output_dir = output_dir
        self.results = []
        
        os.makedirs(output_dir, exist_ok=True)
    
    def extract_domains(self):
        """Extract unique domains from PCAP file"""
        print(f"\n{'='*80}")
        print(f"Extracting domains from: {self.pcap_file}")
        print(f"{'='*80}\n")
        
        try:
            packets = rdpcap(self.pcap_file)
            print(f"Loaded {len(packets)} packets")
        except Exception as e:
            print(f"Error loading PCAP: {e}")
            return []
        
        domains = set()
        
        for packet in packets:
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                dns_layer = packet[DNS]
                if dns_layer.qr == 0:  # Query
                    qname = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                    qtype = dns_layer.qd.qtype
                    
                    # Only process A records
                    if qtype == 1:
                        domains.add(qname)
        
        domains_list = sorted(list(domains))
        print(f"Found {len(domains_list)} unique domains\n")
        
        return domains_list
    
    def test_dns_resolution(self, domain):
        """Test DNS resolution for a domain using dig"""
        start_time = time.time()
        
        try:
            # Use dig to query DNS server
            cmd = f"dig +time=5 +tries=1 @{self.dns_server} {domain} A +short"
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=10
            )
            
            latency = time.time() - start_time
            
            # Parse result
            answers = []
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    # Check if it's an IP address
                    if line and not line.startswith(';'):
                        answers.append(line)
            
            success = len(answers) > 0
            
            return {
                'domain': domain,
                'success': success,
                'latency': latency,
                'answers': answers,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'domain': domain,
                'success': False,
                'latency': time.time() - start_time,
                'answers': [],
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def test_all_domains(self, domains, max_domains=None):
        """Test resolution for all domains"""
        if max_domains:
            domains = domains[:max_domains]
        
        print(f"\n{'='*80}")
        print(f"Testing DNS Resolution for {len(domains)} domains")
        print(f"DNS Server: {self.dns_server}")
        print(f"{'='*80}\n")
        
        results = []
        successful = 0
        failed = 0
        total_latency = 0
        
        for i, domain in enumerate(domains, 1):
            print(f"[{i}/{len(domains)}] Testing: {domain:<50}", end=' ')
            
            result = self.test_dns_resolution(domain)
            results.append(result)
            
            if result['success']:
                successful += 1
                total_latency += result['latency']
                print(f"✓ {result['latency']*1000:.2f}ms ({len(result['answers'])} answers)")
            else:
                failed += 1
                print(f"✗ Failed")
            
            # Small delay between queries
            time.sleep(0.1)
        
        self.results = results
        
        # Calculate statistics
        avg_latency = total_latency / successful if successful > 0 else 0
        success_rate = (successful / len(domains)) * 100 if domains else 0
        
        stats = {
            'pcap_file': os.path.basename(self.pcap_file),
            'dns_server': self.dns_server,
            'total_queries': len(domains),
            'successful': successful,
            'failed': failed,
            'success_rate': success_rate,
            'avg_latency_ms': avg_latency * 1000,
            'timestamp': datetime.now().isoformat()
        }
        
        print(f"\n{'='*80}")
        print("RESULTS SUMMARY")
        print(f"{'='*80}")
        print(f"Total Queries:    {stats['total_queries']}")
        print(f"Successful:       {stats['successful']} ({stats['success_rate']:.1f}%)")
        print(f"Failed:           {stats['failed']}")
        print(f"Avg Latency:      {stats['avg_latency_ms']:.2f} ms")
        print(f"{'='*80}\n")
        
        return stats
    
    def save_results(self, stats):
        """Save results to JSON file"""
        pcap_name = os.path.basename(self.pcap_file).replace('.pcap', '')
        output_file = os.path.join(self.output_dir, f'{pcap_name}_results.json')
        
        data = {
            'statistics': stats,
            'results': self.results
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"✓ Results saved to: {output_file}\n")
        
        # Also save to CSV
        csv_file = os.path.join(self.output_dir, f'{pcap_name}_results.csv')
        with open(csv_file, 'w') as f:
            f.write("Domain,Success,Latency_ms,Num_Answers,Timestamp\n")
            for result in self.results:
                f.write(f"{result['domain']},{result['success']},"
                       f"{result['latency']*1000:.2f},{len(result['answers'])},"
                       f"{result['timestamp']}\n")
        
        print(f"✓ Results saved to: {csv_file}\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 test_dns_from_pcap.py <pcap_file> [max_domains]")
        print("\nExample:")
        print("  python3 test_dns_from_pcap.py data/PCAP_1_H1.pcap")
        print("  python3 test_dns_from_pcap.py data/PCAP_1_H1.pcap 10")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    max_domains = int(sys.argv[2]) if len(sys.argv) > 2 else None
    
    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file not found: {pcap_file}")
        sys.exit(1)
    
    # Create tester
    tester = PCAPDNSTester(pcap_file)
    
    # Extract domains
    domains = tester.extract_domains()
    
    if not domains:
        print("No domains found in PCAP file")
        sys.exit(1)
    
    # Test DNS resolution
    stats = tester.test_all_domains(domains, max_domains)
    
    # Save results
    tester.save_results(stats)
    
    print("\nTo view detailed DNS logs:")
    print("  cat /tmp/dns_resolver.log")
    print("  cat /tmp/dns_queries.json")


if __name__ == '__main__':
    main()
